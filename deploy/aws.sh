#!/usr/bin/env bash
# chutchut's inbound mail on AWS, in eu-west-1: one S3 bucket for the raw messages, one SNS topic that tells chutchut a
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
# The topic signs with SHA256 (SignatureVersion 2), the only version chutchut's webhook accepts, and only SES from this
# account, for this rule, may publish to it. It's encrypted with its own KMS key, which SES may use only for this rule,
# and only this account may subscribe to it, only over HTTPS. The rule requires TLS from the sending server and asks SES for its spam
# and virus verdicts. GuardDuty Malware Protection for S3 scans each new object under in/ and tags it with the result
# (GuardDutyMalwareScanStatus).
#
# SES's notice reaches the topic before GuardDuty's tag reaches the object, so whatever reads a message waits for its
# tag to say NO_THREATS_FOUND before reading its body or any attachment, and holds it otherwise.
set -euo pipefail

MODE=${1:-}
REGION=${AWS_REGION:-eu-west-1}
NAME=${CHUTCHUT_NAME:-chutchut}
BUCKET=${CHUTCHUT_BUCKET:?CHUTCHUT_BUCKET names the bucket}
TOPIC=$NAME-inbound
TOPIC_KEY=alias/$NAME-inbound-topic
RULE_SET=$NAME
RULE=$NAME-inbound
SCAN_ROLE=$NAME-malware-scan
PREFIX=in/
DAYS=30

aws() ( command aws --region "$REGION" --output text "$@" )

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

if [[ "$MODE" == policies ]]; then
  # A made-up account, so the shapes can be read and tested with no AWS access.
  account=000000000000 arn="arn:aws:sns:$REGION:000000000000:$TOPIC"
  printf '%s\n' "{\"bucket\":$(bucket_policy $account),\"topic\":$(topic_policy $account "$arn"),\"topic_key\":$(topic_key_policy $account),\"lifecycle\":$(lifecycle),\"scan_trust\":$(scan_trust),\"scan\":$(scan_policy $account)}"
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

bucket
arn=$(topic)
scan
rule "$arn"
activate
echo "chutchut inbound: bucket $BUCKET, topic $TOPIC, rule $RULE_SET/$RULE in $REGION$([[ "$ACTIVATE" == yes ]] && echo ', active' || echo ', not active')"
