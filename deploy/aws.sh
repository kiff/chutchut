#!/usr/bin/env bash
# chutchut's inbound mail on AWS, in eu-west-1: one S3 bucket for the raw messages, one DynamoDB table for what's
# filed, one SNS topic that tells chutchut a
# message arrived, one SES receipt rule that writes each message to the bucket and notifies the topic, and GuardDuty
# scanning each message for malware. Idempotent: a rerun brings each piece back to what this file says. It never
# prints an account id or an ARN, and it removes nothing.
#
#   deploy/aws.sh up         create or update everything above
#   deploy/aws.sh policies   print the policies it would set, as JSON, without calling AWS (for review and tests)
#
# Environment:
#   CHUTCHUT_BUCKET      the bucket's name (required: bucket names are global)
#   CHUTCHUT_RECIPIENTS  the addresses or domains SES receives for, comma-separated (required for up)
#   CHUTCHUT_NAME        the prefix for the topic, the rule set, the rule and the scan's role (default chutchut)
#   CHUTCHUT_PAIRED      the paired senders' addresses, comma-separated (until pairing is kept in the table)
#   CHUTCHUT_MODE        "inbox" (default) or "tafs": chutchut as tafs cloud's mail provider. tafs mode needs:
#   CHUTCHUT_TAFS_WEBHOOK  tafs cloud's email webhook (https://…/v1/doors/email)
#   CHUTCHUT_WEBHOOK_SECRET_PARAM  the SSM SecureString holding the webhook's signing secret
#   CHUTCHUT_READ_KEY_PARAM        the SSM SecureString holding the SHA-256 (hex) of tafs's read key
#                        Both parameters are put there by their owner, never by this script or in this repository.
#   CHUTCHUT_ALERT_EMAIL an address the daily alert is mailed to (optional: it confirms by mail before any arrives)
#   AWS_REGION           default eu-west-1, where SES receives mail
#   CHUTCHUT_ACTIVATE    "yes" makes chutchut's rule set the region's active one. SES has one active rule set per region, so
#                        it's off unless asked for, and refused while another set is active: activating would silently
#                        stop the mail that set receives.
#
# The bucket:
#   - Block Public Access on every setting, and a policy that refuses any request not over TLS;
#   - only SES may write, only under in/, and only for this account's own rule (aws:SourceAccount, aws:SourceArn), so
#     another account's SES can't write here (the confused deputy);
#   - encrypted at rest (SSE-S3), and raw messages under in/ are deleted after 30 days: the mail a person keeps lives
#     in chutchut's own store, not here.
# The table holds what the webhook files (never a message's body): on-demand, encrypted, with point-in-time recovery
# and deletion protection on, and a TTL on expiresAt that removes a knock after 30 days and a day's counter after two.
# The topic signs with SHA256 (SignatureVersion 2), the only version chutchut's webhook accepts, and only SES from this
# account, for this rule, may publish to it. It's encrypted with its own KMS key, which SES may use only for this rule,
# and only this account may subscribe to it, only over HTTPS. The rule requires TLS from the sending server and asks SES for its spam
# and virus verdicts. GuardDuty Malware Protection for S3 scans each new object under in/ and tags it with the result
# (GuardDutyMalwareScanStatus).
#
# The functions (built by `npm run build`, Node 22 on arm64, logs kept 30 days), each with a role that may do only
# what it does:
#   - the webhook, behind a function URL that SNS posts to (subscribed over HTTPS): reads and writes the table;
#   - the reader, sent GuardDuty's scan result for in/ by an EventBridge rule: reads and updates the table, reads in/
#     and writes kept/ (where a paired sender's clean mail is kept, outside the 30-day lifecycle);
#   - the daily stale check: reads the table and publishes to the alerts topic.
#
# SES's notice reaches the topic before GuardDuty's tag reaches the object, so whatever reads a message waits for its
# tag to say NO_THREATS_FOUND before reading its body or any attachment, and holds it otherwise.
set -euo pipefail

MODE=${1:-}
REGION=${AWS_REGION:-eu-west-1}
NAME=${CHUTCHUT_NAME:-chutchut}
BUCKET=${CHUTCHUT_BUCKET:?CHUTCHUT_BUCKET names the bucket}
TOPIC=$NAME-inbound
ALERTS=$NAME-alerts
FUNCTIONS="webhook reader stale"
MODE_=${CHUTCHUT_MODE:-inbox}
[[ "$MODE_" == inbox || "$MODE_" == tafs ]] || { echo "CHUTCHUT_MODE is inbox or tafs" >&2; exit 2; }
[[ "$MODE_" == tafs ]] && FUNCTIONS="$FUNCTIONS provider"
TABLE=$NAME-mail
TOPIC_KEY=alias/$NAME-inbound-topic
RULE_SET=$NAME
RULE=$NAME-inbound
SCAN_ROLE=$NAME-malware-scan
PREFIX=in/
DAYS=30

aws() ( command aws --region "$REGION" --output text "$@" )
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST=${CHUTCHUT_DIST:-$ROOT/dist}

bucket_policy() { # account
  cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Sid":"TlsOnly","Effect":"Deny","Principal":"*","Action":"s3:*",
  "Resource":["arn:aws:s3:::$BUCKET","arn:aws:s3:::$BUCKET/*"],
  "Condition":{"Bool":{"aws:SecureTransport":"false"}}},
 {"Sid":"SesWritesOnlyForThisRule","Effect":"Allow","Principal":{"Service":"ses.amazonaws.com"},"Action":"s3:PutObject",
  "Resource":"arn:aws:s3:::$BUCKET/$PREFIX*",
  "Condition":{"StringEquals":{"aws:SourceAccount":"$1"},
   "ArnLike":{"aws:SourceArn":"arn:aws:ses:$REGION:$1:receipt-rule-set/$RULE_SET:receipt-rule/$RULE"}}}
]}
JSON
}

topic_policy() { # account topic-arn
  cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Sid":"SesPublishesOnlyForThisRule","Effect":"Allow","Principal":{"Service":"ses.amazonaws.com"},"Action":"SNS:Publish",
  "Resource":"$2",
  "Condition":{"StringEquals":{"AWS:SourceAccount":"$1"},
   "ArnLike":{"AWS:SourceArn":"arn:aws:ses:$REGION:$1:receipt-rule-set/$RULE_SET:receipt-rule/$RULE"}}},
 {"Sid":"SubscribeOnlyFromThisAccount","Effect":"Deny","Principal":"*","Action":"SNS:Subscribe","Resource":"$2",
  "Condition":{"StringNotEquals":{"aws:PrincipalAccount":"$1"}}},
 {"Sid":"SubscribeOnlyOverHttps","Effect":"Deny","Principal":"*","Action":"SNS:Subscribe","Resource":"$2",
  "Condition":{"StringNotEquals":{"SNS:Protocol":"https"}}}
]}
JSON
}

# The topic's key: this account administers it, and SES may use it only to publish for this rule.
topic_key_policy() { # account
  cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Sid":"Account","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::$1:root"},"Action":"kms:*","Resource":"*"},
 {"Sid":"SesForThisRule","Effect":"Allow","Principal":{"Service":"ses.amazonaws.com"},"Action":["kms:GenerateDataKey*","kms:Decrypt"],
  "Resource":"*",
  "Condition":{"StringEquals":{"aws:SourceAccount":"$1"},
   "ArnLike":{"aws:SourceArn":"arn:aws:ses:$REGION:$1:receipt-rule-set/$RULE_SET:receipt-rule/$RULE"}}}
]}
JSON
}

lifecycle() {
  cat <<JSON
{"Rules":[{"ID":"raw-mail-$DAYS-days","Status":"Enabled","Filter":{"Prefix":"$PREFIX"},"Expiration":{"Days":$DAYS}}]}
JSON
}

scan_trust() {
  cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"malware-protection-plan.guardduty.amazonaws.com"},
 "Action":"sts:AssumeRole"}]}
JSON
}

# What GuardDuty needs to scan and tag objects under in/ in this bucket, and nothing else.
scan_policy() { # account
  cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Sid":"Events","Effect":"Allow","Action":["events:PutRule","events:DeleteRule","events:PutTargets","events:RemoveTargets"],
  "Resource":"arn:aws:events:$REGION:$1:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*",
  "Condition":{"StringLike":{"events:ManagedBy":"malware-protection-plan.guardduty.amazonaws.com"}}},
 {"Sid":"EventsRead","Effect":"Allow","Action":["events:DescribeRule","events:ListTargetsByRule"],
  "Resource":"arn:aws:events:$REGION:$1:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"},
 {"Sid":"Notifications","Effect":"Allow","Action":["s3:PutBucketNotification","s3:GetBucketNotification"],
  "Resource":"arn:aws:s3:::$BUCKET"},
 {"Sid":"Validation","Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::$BUCKET/malware-protection-resource-validation-object"},
 {"Sid":"ScanAndTag","Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObjectTagging","s3:GetObjectTagging","s3:PutObjectVersionTagging","s3:GetObjectVersionTagging"],
  "Resource":"arn:aws:s3:::$BUCKET/$PREFIX*"}
]}
JSON
}

lambda_trust() {
  cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
JSON
}

logs_statement() { # account function
  printf '%s' "{\"Sid\":\"Logs\",\"Effect\":\"Allow\",\"Action\":[\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":\"arn:aws:logs:$REGION:$1:log-group:/aws/lambda/$NAME-$2:*\"}"
}

# Each function's role: only what it does, on only its own resources.
function_policy() { # account function
  local table="arn:aws:dynamodb:$REGION:$1:table/$TABLE" own
  case "$2" in
    webhook) own="{\"Sid\":\"Table\",\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\",\"dynamodb:UpdateItem\"],\"Resource\":\"$table\"}" ;;
    reader) own="{\"Sid\":\"Table\",\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:UpdateItem\"],\"Resource\":\"$table\"},
 {\"Sid\":\"Failed\",\"Effect\":\"Allow\",\"Action\":\"sns:Publish\",\"Resource\":\"arn:aws:sns:$REGION:$1:$ALERTS\"}"
      if [[ "$MODE_" == tafs ]]; then
        # tafs mode keeps nothing for good: no kept/; it signs tafs's webhook with the secret in SSM.
        own="$own,
 {\"Sid\":\"WebhookSecret\",\"Effect\":\"Allow\",\"Action\":\"ssm:GetParameter\",\"Resource\":\"arn:aws:ssm:$REGION:$1:parameter${WEBHOOK_SECRET_PARAM}\"}"
      else
        # The copy to kept/ keeps GuardDuty's scan tag: read on in/, written on kept/.
        own="$own,
 {\"Sid\":\"ReadIn\",\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:GetObjectTagging\"],\"Resource\":\"arn:aws:s3:::$BUCKET/$PREFIX*\"},
 {\"Sid\":\"WriteKept\",\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:PutObjectTagging\"],\"Resource\":\"arn:aws:s3:::$BUCKET/kept/*\"}"
      fi ;;
    provider) own="{\"Sid\":\"Table\",\"Effect\":\"Allow\",\"Action\":\"dynamodb:GetItem\",\"Resource\":\"$table\"},
 {\"Sid\":\"ReadIn\",\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/$PREFIX*\"},
 {\"Sid\":\"ReadKey\",\"Effect\":\"Allow\",\"Action\":\"ssm:GetParameter\",\"Resource\":\"arn:aws:ssm:$REGION:$1:parameter${READ_KEY_PARAM}\"}" ;;
    stale) own="{\"Sid\":\"Table\",\"Effect\":\"Allow\",\"Action\":\"dynamodb:Scan\",\"Resource\":\"$table\"},
 {\"Sid\":\"Alert\",\"Effect\":\"Allow\",\"Action\":\"sns:Publish\",\"Resource\":\"arn:aws:sns:$REGION:$1:$ALERTS\"}" ;;
  esac
  printf '%s' "{\"Version\":\"2012-10-17\",\"Statement\":[$own,
 $(logs_statement "$1" "$2")]}"
}

# GuardDuty's scan result for this bucket, to the reader.
scan_rule_pattern() {
  cat <<JSON
{"source":["aws.guardduty"],"detail-type":["GuardDuty Malware Protection Object Scan Result"],
 "detail":{"s3ObjectDetails":{"bucketName":["$BUCKET"]}}}
JSON
}

if [[ "$MODE" == policies ]]; then
  # A made-up account (and, in tafs mode, made-up parameter names), so the shapes can be read and tested with no AWS access.
  account=000000000000 arn="arn:aws:sns:$REGION:000000000000:$TOPIC"
  WEBHOOK_SECRET_PARAM=/chutchut/webhook-secret READ_KEY_PARAM=/chutchut/read-key
  provider=""
  [[ "$MODE_" == tafs ]] && provider=",\"provider\":$(function_policy $account provider)"
  printf '%s\n' "{\"bucket\":$(bucket_policy $account),\"topic\":$(topic_policy $account "$arn"),\"topic_key\":$(topic_key_policy $account),\"lifecycle\":$(lifecycle),\"scan_trust\":$(scan_trust),\"scan\":$(scan_policy $account),\"lambda_trust\":$(lambda_trust),\"webhook\":$(function_policy $account webhook),\"reader\":$(function_policy $account reader),\"stale\":$(function_policy $account stale),\"scan_rule\":$(scan_rule_pattern)$provider}"
  exit 0
fi
[[ "$MODE" == up ]] || { echo "usage: deploy/aws.sh up | policies" >&2; exit 2; }
RECIPIENTS=${CHUTCHUT_RECIPIENTS:?CHUTCHUT_RECIPIENTS names the addresses or domains SES receives for}
# Each an address or a domain, nothing else: a typo here would receive mail for the wrong name, or none.
RECIPIENT='^([A-Za-z0-9._%+-]+@)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
IFS=, read -r -a recipient_list <<<"$RECIPIENTS"
for r in "${recipient_list[@]}"; do
  r=${r#"${r%%[![:space:]]*}"} r=${r%"${r##*[![:space:]]}"} # trimmed at both ends only
  [[ "$r" =~ $RECIPIENT ]] || { echo "CHUTCHUT_RECIPIENTS: not an address or a domain: $r" >&2; exit 2; }
done
# tafs mode's settings, checked before AWS is called.
TAFS_WEBHOOK="" WEBHOOK_SECRET_PARAM="" READ_KEY_PARAM=""
if [[ "$MODE_" == tafs ]]; then
  TAFS_WEBHOOK=${CHUTCHUT_TAFS_WEBHOOK:?tafs mode needs CHUTCHUT_TAFS_WEBHOOK}
  WEBHOOK_SECRET_PARAM=${CHUTCHUT_WEBHOOK_SECRET_PARAM:?tafs mode needs CHUTCHUT_WEBHOOK_SECRET_PARAM}
  READ_KEY_PARAM=${CHUTCHUT_READ_KEY_PARAM:?tafs mode needs CHUTCHUT_READ_KEY_PARAM}
  [[ "$TAFS_WEBHOOK" =~ ^https://[a-z0-9.-]+(:[0-9]+)?/v1/doors/email$ ]] || { echo "CHUTCHUT_TAFS_WEBHOOK isn't tafs cloud's email webhook" >&2; exit 2; }
  for p in "$WEBHOOK_SECRET_PARAM" "$READ_KEY_PARAM"; do
    [[ "$p" =~ ^/[A-Za-z0-9_./-]+$ ]] || { echo "not an SSM parameter name: $p" >&2; exit 2; }
  done
fi

# The paired senders: each an address, joined by commas.
PAIRED=""
if [[ -n "${CHUTCHUT_PAIRED:-}" ]]; then
  IFS=, read -r -a paired_list <<<"$CHUTCHUT_PAIRED"
  for a in "${paired_list[@]}"; do
    a=${a#"${a%%[![:space:]]*}"} a=${a%"${a##*[![:space:]]}"}
    [[ "$a" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] \
      || { echo "CHUTCHUT_PAIRED: not an address: $a" >&2; exit 2; }
    PAIRED+="${PAIRED:+,}$a"
  done
fi
[[ -f "$DIST/webhook.mjs" && -f "$DIST/reader.mjs" && -f "$DIST/stale.mjs" && -f "$DIST/provider.mjs" ]] \
  || { echo "build the functions first: npm run build" >&2; exit 2; }
ACTIVATE=${CHUTCHUT_ACTIVATE:-}
[[ -z "$ACTIVATE" || "$ACTIVATE" == yes ]] || { echo "CHUTCHUT_ACTIVATE is yes or unset" >&2; exit 2; }

# A failure inside $(…) stops the run too, so a topic, key or policy that wasn't set is never reported as done. That needs
# bash 4.4 or later (macOS's own /bin/bash is 3.2: use Homebrew's).
if ! shopt -s inherit_errexit 2>/dev/null; then echo "deploy/aws.sh needs bash 4.4 or later" >&2; exit 2; fi
# (Only `up` calls AWS, so only `up` needs it: `policies` and the checks above run on any bash.)
ACCOUNT=$(aws sts get-caller-identity --query Account)

bucket() {
  if ! aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
    aws s3api create-bucket --bucket "$BUCKET" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi
  aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-ownership-controls --bucket "$BUCKET" --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
  aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
  aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" --lifecycle-configuration "$(lifecycle)"
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(bucket_policy "$ACCOUNT")"
}

# Whether the key's alias exists: a missing alias is "no", and any other error stops the run, so a failed read never
# makes a second key.
key_exists() {
  local err; err=$(mktemp)
  if aws kms describe-key --key-id "$TOPIC_KEY" --query KeyMetadata.KeyId >/dev/null 2>"$err"; then rm -f "$err"; return 0; fi
  if grep -q NotFoundException "$err"; then rm -f "$err"; return 1; fi
  cat "$err" >&2; rm -f "$err"; exit 1
}

table() {
  local err; err=$(mktemp)
  if ! aws dynamodb describe-table --table-name "$TABLE" --query Table.TableName >/dev/null 2>"$err"; then
    if ! grep -q ResourceNotFoundException "$err"; then cat "$err" >&2; rm -f "$err"; exit 1; fi
    aws dynamodb create-table --table-name "$TABLE" --billing-mode PAY_PER_REQUEST \
      --attribute-definitions AttributeName=pk,AttributeType=S --key-schema AttributeName=pk,KeyType=HASH \
      --sse-specification Enabled=true --deletion-protection-enabled --query TableDescription.TableName >/dev/null
    aws dynamodb wait table-exists --table-name "$TABLE"
  fi
  rm -f "$err"
  aws dynamodb update-continuous-backups --table-name "$TABLE" \
    --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true >/dev/null
  if [[ "$(aws dynamodb describe-time-to-live --table-name "$TABLE" --query TimeToLiveDescription.TimeToLiveStatus)" != ENABLED ]]; then
    aws dynamodb update-time-to-live --table-name "$TABLE" --time-to-live-specification Enabled=true,AttributeName=expiresAt >/dev/null
  fi
}

topic_key() { # prints the key's id
  local id
  if key_exists; then
    id=$(aws kms describe-key --key-id "$TOPIC_KEY" --query KeyMetadata.KeyId)
  else
    id=$(aws kms create-key --description "$NAME inbound topic" --query KeyMetadata.KeyId)
    aws kms create-alias --alias-name "$TOPIC_KEY" --target-key-id "$id"
  fi
  aws kms put-key-policy --key-id "$id" --policy-name default --policy "$(topic_key_policy "$ACCOUNT")"
  aws kms enable-key-rotation --key-id "$id"
  echo "$id"
}

topic() { # prints the topic's ARN, for the rule
  local key; key=$(topic_key)
  local arn; arn=$(aws sns create-topic --name "$TOPIC" --query TopicArn)
  aws sns set-topic-attributes --topic-arn "$arn" --attribute-name KmsMasterKeyId --attribute-value "$key"
  aws sns set-topic-attributes --topic-arn "$arn" --attribute-name SignatureVersion --attribute-value 2
  aws sns set-topic-attributes --topic-arn "$arn" --attribute-name Policy --attribute-value "$(topic_policy "$ACCOUNT" "$arn")"
  echo "$arn"
}

rule() { # topic-arn
  local recipients; recipients=$(printf '%s' "$RECIPIENTS" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | awk 'NF{printf "%s\"%s\"", (n++?",":""), $0}')
  local body
  body="{\"Name\":\"$RULE\",\"Enabled\":true,\"TlsPolicy\":\"Require\",\"ScanEnabled\":true,\"Recipients\":[$recipients],
    \"Actions\":[{\"S3Action\":{\"BucketName\":\"$BUCKET\",\"ObjectKeyPrefix\":\"$PREFIX\",\"TopicArn\":\"$1\"}}]}"
  if ! aws ses describe-receipt-rule-set --rule-set-name "$RULE_SET" >/dev/null 2>&1; then
    aws ses create-receipt-rule-set --rule-set-name "$RULE_SET" >/dev/null
  fi
  if aws ses describe-receipt-rule --rule-set-name "$RULE_SET" --rule-name "$RULE" >/dev/null 2>&1; then
    aws ses update-receipt-rule --rule-set-name "$RULE_SET" --rule "$body"
  else
    aws ses create-receipt-rule --rule-set-name "$RULE_SET" --rule "$body"
  fi
}

# Last, once the bucket, the topic, the scan and the rule are all in place: nothing arrives before it can be scanned.
activate() {
  [[ "$ACTIVATE" == yes ]] || return 0
  # A failed read stops the run (errexit): it never counts as "none active".
  local active; active=$(aws ses describe-active-receipt-rule-set --query Metadata.Name)
  if [[ -n "$active" && "$active" != None && "$active" != "$RULE_SET" ]]; then
    echo "another SES rule set is active in $REGION: activating $RULE_SET would stop the mail it receives. Not activated." >&2
    exit 3
  fi
  aws ses set-active-receipt-rule-set --rule-set-name "$RULE_SET"
}

scan() {
  if ! aws iam get-role --role-name "$SCAN_ROLE" --query Role.RoleName >/dev/null 2>&1; then
    aws iam create-role --role-name "$SCAN_ROLE" --assume-role-policy-document "$(scan_trust)" --query Role.RoleName >/dev/null
    sleep 10 # IAM is eventually consistent
  fi
  aws iam put-role-policy --role-name "$SCAN_ROLE" --policy-name scan --policy-document "$(scan_policy "$ACCOUNT")"
  local role_arn; role_arn=$(aws iam get-role --role-name "$SCAN_ROLE" --query Role.Arn)
  local plans; plans=$(aws guardduty list-malware-protection-plans --query 'MalwareProtectionPlans[].MalwareProtectionPlanId')
  local plan=""
  for id in $plans; do
    if [[ "$(aws guardduty get-malware-protection-plan --malware-protection-plan-id "$id" --query ProtectedResource.S3Bucket.BucketName)" == "$BUCKET" ]]; then plan=$id; fi
  done
  if [[ -z "$plan" ]]; then
    aws guardduty create-malware-protection-plan --role "$role_arn" \
      --protected-resource "{\"S3Bucket\":{\"BucketName\":\"$BUCKET\",\"ObjectPrefixes\":[\"$PREFIX\"]}}" \
      --actions '{"Tagging":{"Status":"ENABLED"}}' --query MalwareProtectionPlanId >/dev/null
  fi
}

# The alerts topic: the daily stale check publishes here; an address, if given, is subscribed (it confirms by mail).
alerts() {
  local arn; arn=$(aws sns create-topic --name "$ALERTS" --query TopicArn)
  if [[ -n "${CHUTCHUT_ALERT_EMAIL:-}" ]]; then
    if ! aws sns list-subscriptions-by-topic --topic-arn "$arn" --query 'Subscriptions[].Endpoint' | tr '\t' '\n' | grep -qx "$CHUTCHUT_ALERT_EMAIL"; then
      aws sns subscribe --topic-arn "$arn" --protocol email --notification-endpoint "$CHUTCHUT_ALERT_EMAIL" >/dev/null
    fi
  fi
  echo "$arn"
}

# One function: its role and policy, its code (dist/<name>.mjs as index.mjs), its settings, and its logs kept 30 days.
function_up() { # name topic-arn alerts-arn
  local fn=$NAME-$1 role=$NAME-$1
  if ! aws iam get-role --role-name "$role" --query Role.RoleName >/dev/null 2>&1; then
    aws iam create-role --role-name "$role" --assume-role-policy-document "$(lambda_trust)" --query Role.RoleName >/dev/null
    sleep 10 # IAM is eventually consistent
  fi
  aws iam put-role-policy --role-name "$role" --policy-name "$1" --policy-document "$(function_policy "$ACCOUNT" "$1")"
  local role_arn; role_arn=$(aws iam get-role --role-name "$role" --query Role.Arn)
  local dir; dir=$(mktemp -d)
  cp "$DIST/$1.mjs" "$dir/index.mjs"
  (cd "$dir" && zip -q function.zip index.mjs)
  # Every value is checked above (names, ARNs, addresses), so none can carry a quote into this JSON.
  local env="{\"Variables\":{\"CHUTCHUT_BUCKET\":\"$BUCKET\",\"CHUTCHUT_TABLE\":\"$TABLE\",\"CHUTCHUT_TOPIC_ARN\":\"$2\",\"CHUTCHUT_ALERTS_ARN\":\"$3\",\"CHUTCHUT_PAIRED\":\"$PAIRED\",\"CHUTCHUT_MODE\":\"$MODE_\",\"CHUTCHUT_TAFS_WEBHOOK\":\"$TAFS_WEBHOOK\",\"CHUTCHUT_WEBHOOK_SECRET_PARAM\":\"$WEBHOOK_SECRET_PARAM\",\"CHUTCHUT_READ_KEY_PARAM\":\"$READ_KEY_PARAM\",\"CHUTCHUT_RECIPIENTS\":\"$(printf '%s' "$RECIPIENTS" | tr -d ' ')\"}}"
  if aws lambda get-function --function-name "$fn" --query Configuration.FunctionName >/dev/null 2>&1; then
    aws lambda update-function-code --function-name "$fn" --zip-file "fileb://$dir/function.zip" --query FunctionName >/dev/null
    aws lambda wait function-updated-v2 --function-name "$fn"
  else
    local i
    for i in 1 2 3 4 5; do # a new role takes a moment to be assumable
      if aws lambda create-function --function-name "$fn" --runtime nodejs22.x --architectures arm64 --handler index.handler \
        --role "$role_arn" --zip-file "fileb://$dir/function.zip" --timeout 30 --memory-size 256 --query FunctionName >/dev/null 2>&1; then break; fi
      [[ $i == 5 ]] && { echo "couldn't create $fn" >&2; exit 1; }
      sleep 5
    done
    aws lambda wait function-active-v2 --function-name "$fn"
  fi
  aws lambda update-function-configuration --function-name "$fn" --environment "$env" --query FunctionName >/dev/null
  aws lambda wait function-updated-v2 --function-name "$fn"
  if [[ -z "$(aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/$fn" --query "logGroups[?logGroupName=='/aws/lambda/$fn'].logGroupName")" ]]; then
    aws logs create-log-group --log-group-name "/aws/lambda/$fn"
  fi
  aws logs put-retention-policy --log-group-name "/aws/lambda/$fn" --retention-in-days 30
  rm -rf "$dir"
}

# The webhook's public URL, subscribed to the topic over HTTPS: the webhook confirms the subscription itself.
webhook_up() { # topic-arn
  local fn=$NAME-webhook url
  if ! aws lambda get-function-url-config --function-name "$fn" --query FunctionUrl >/dev/null 2>&1; then
    aws lambda create-function-url-config --function-name "$fn" --auth-type NONE --query FunctionUrl >/dev/null
    aws lambda add-permission --function-name "$fn" --statement-id url --action lambda:InvokeFunctionUrl \
      --principal '*' --function-url-auth-type NONE >/dev/null
  fi
  url=$(aws lambda get-function-url-config --function-name "$fn" --query FunctionUrl)
  if ! aws sns list-subscriptions-by-topic --topic-arn "$1" --query 'Subscriptions[].Endpoint' | tr '\t' '\n' | grep -qx "$url"; then
    aws sns subscribe --topic-arn "$1" --protocol https --notification-endpoint "$url" >/dev/null
  fi
}

# An EventBridge rule that invokes one function: GuardDuty's result for the reader, a daily schedule for the check.
trigger() { # rule function (--event-pattern JSON | --schedule-expression EXPR)
  local rule=$NAME-$1 fn=$NAME-$2 kind=$3 value=$4
  local rule_arn; rule_arn=$(aws events put-rule --name "$rule" "$kind" "$value" --query RuleArn)
  local fn_arn; fn_arn=$(aws lambda get-function --function-name "$fn" --query Configuration.FunctionArn)
  aws events put-targets --rule "$rule" --targets "Id=$2,Arn=$fn_arn" >/dev/null
  if ! aws lambda get-policy --function-name "$fn" --query Policy 2>/dev/null | grep -q "\"$rule\""; then
    aws lambda add-permission --function-name "$fn" --statement-id "$rule" --action lambda:InvokeFunction \
      --principal events.amazonaws.com --source-arn "$rule_arn" >/dev/null
  fi
}


bucket
table
arn=$(topic)
alerts_arn=$(alerts)
scan
for f in $FUNCTIONS; do function_up "$f" "$arn" "$alerts_arn"; done
# The public webhook can't take more than a few at once, so a flood can't run up the table or the account's Lambda room.
aws lambda put-function-concurrency --function-name "$NAME-webhook" --reserved-concurrent-executions 10 >/dev/null
# tafs's read and send take the provider's public URL: at most 10 at once too.
[[ "$MODE_" == tafs ]] && aws lambda put-function-concurrency --function-name "$NAME-provider" --reserved-concurrent-executions 10 >/dev/null
# A scan result the reader couldn't handle after EventBridge's retries is raised on the alerts topic, never dropped.
aws lambda put-function-event-invoke-config --function-name "$NAME-reader" --maximum-retry-attempts 2 \
  --destination-config "{\"OnFailure\":{\"Destination\":\"$alerts_arn\"}}" >/dev/null
webhook_up "$arn"
# tafs mode: the read API's own function URL (tafs's read key is checked in the code); it prints it for tafs's setting.
if [[ "$MODE_" == tafs ]]; then
  if ! aws lambda get-function-url-config --function-name "$NAME-provider" --query FunctionUrl >/dev/null 2>&1; then
    aws lambda create-function-url-config --function-name "$NAME-provider" --auth-type NONE --query FunctionUrl >/dev/null
    aws lambda add-permission --function-name "$NAME-provider" --statement-id url --action lambda:InvokeFunctionUrl \
      --principal '*' --function-url-auth-type NONE >/dev/null
  fi
  echo "tafs cloud's provider URL: $(aws lambda get-function-url-config --function-name "$NAME-provider" --query FunctionUrl)"
fi
trigger scanned reader --event-pattern "$(scan_rule_pattern)"
trigger stale-daily stale --schedule-expression "rate(1 day)"
rule "$arn"
activate
echo "chutchut inbound: bucket $BUCKET, table $TABLE, topic $TOPIC, rule $RULE_SET/$RULE in $REGION$([[ "$ACTIVATE" == yes ]] && echo ', active' || echo ', not active')"
