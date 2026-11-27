import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The policies deploy/aws.sh sets, read with no AWS access (its `policies` mode, a made-up account).
const policies = JSON.parse(
  execFileSync("bash", ["deploy/aws.sh", "policies"], { env: { ...process.env, CHUTCHUT_BUCKET: "chutchut-inbound-test", AWS_REGION: "eu-west-1" } }).toString(),
);
const rule = "arn:aws:ses:eu-west-1:000000000000:receipt-rule-set/chutchut:receipt-rule/chutchut-inbound";

describe("deploy", () => {
  it("lets only SES write to the bucket, only under in/, only for this account's own rule", () => {
    const allow = policies.bucket.Statement.filter((s: { Effect: string }) => s.Effect === "Allow");
    expect(allow).toHaveLength(1);
    expect(allow[0]).toMatchObject({
      Principal: { Service: "ses.amazonaws.com" }, Action: "s3:PutObject", Resource: "arn:aws:s3:::chutchut-inbound-test/in/*",
      Condition: { StringEquals: { "aws:SourceAccount": "000000000000" }, ArnLike: { "aws:SourceArn": rule } },
    });
  });

  it("refuses every request to the bucket that isn't over TLS", () => {
    expect(policies.bucket.Statement).toContainEqual(expect.objectContaining({
      Effect: "Deny", Principal: "*", Action: "s3:*", Condition: { Bool: { "aws:SecureTransport": "false" } },
    }));
  });

  it("deletes raw mail under in/ after 30 days, and nothing else", () => {
    expect(policies.lifecycle.Rules).toEqual([
      { ID: "raw-mail-30-days", Status: "Enabled", Filter: { Prefix: "in/" }, Expiration: { Days: 30 } },
    ]);
  });

  it("lets only SES publish to the topic, for this account's own rule", () => {
    expect(policies.topic.Statement.filter((s: { Effect: string }) => s.Effect === "Allow")).toEqual([expect.objectContaining({
      Effect: "Allow", Principal: { Service: "ses.amazonaws.com" }, Action: "SNS:Publish",
      Condition: { StringEquals: { "AWS:SourceAccount": "000000000000" }, ArnLike: { "AWS:SourceArn": rule } },
    })]);
  });

  it("gives the malware scan only this bucket's in/ objects to read and tag", () => {
    expect(policies.scan_trust.Statement[0].Principal).toEqual({ Service: "malware-protection-plan.guardduty.amazonaws.com" });
    const objects = policies.scan.Statement.find((s: { Sid: string }) => s.Sid === "ScanAndTag");
    expect(objects.Resource).toBe("arn:aws:s3:::chutchut-inbound-test/in/*");
    for (const s of policies.scan.Statement) {
      expect(JSON.stringify(s.Resource)).not.toBe('"*"');
      expect(([] as string[]).concat(s.Action).some((a) => a === "s3:DeleteObject" || a === "s3:*")).toBe(false);
    }
  });

  it("encrypts the topic with a key SES may use only for this rule, and lets only this account subscribe, over HTTPS", () => {
    const ses = policies.topic_key.Statement.find((s: { Sid: string }) => s.Sid === "SesForThisRule");
    expect(ses).toMatchObject({ Action: ["kms:GenerateDataKey*", "kms:Decrypt"], Condition: { StringEquals: { "aws:SourceAccount": "000000000000" }, ArnLike: { "aws:SourceArn": rule } } });
    const denies = policies.topic.Statement.filter((s: { Effect: string }) => s.Effect === "Deny");
    expect(denies).toEqual([
      expect.objectContaining({ Action: "SNS:Subscribe", Condition: { StringNotEquals: { "aws:PrincipalAccount": "000000000000" } } }),
      expect.objectContaining({ Action: "SNS:Subscribe", Condition: { StringNotEquals: { "SNS:Protocol": "https" } } }),
    ]);
  });

  it("refuses a recipient that isn't an address or a domain, before calling AWS", () => {
    for (const bad of ["support", "support@", "@kiff.test", "a b@kiff.test", "kiff.test;rm", "ok.test,bad"]) {
      let code = 0;
      try {
        execFileSync("bash", ["deploy/aws.sh", "up"], { env: { PATH: "/usr/bin:/bin", CHUTCHUT_BUCKET: "b", CHUTCHUT_RECIPIENTS: bad }, stdio: "pipe" });
      } catch (e) {
        code = (e as { status: number }).status;
      }
      expect(code, bad).toBe(2);
    }
  });

  it("gives each function only what it does, on only its own resources", () => {
    const table = "arn:aws:dynamodb:eu-west-1:000000000000:table/chutchut-mail";
    const actions = (p: { Statement: { Action: string | string[]; Resource: string }[] }) =>
      p.Statement.flatMap((s) => ([] as string[]).concat(s.Action).map((a) => `${a} ${s.Resource}`)).sort();
    const logs = (f: string) => [
      `logs:CreateLogStream arn:aws:logs:eu-west-1:000000000000:log-group:/aws/lambda/chutchut-${f}:*`,
      `logs:PutLogEvents arn:aws:logs:eu-west-1:000000000000:log-group:/aws/lambda/chutchut-${f}:*`,
    ];
    expect(actions(policies.webhook)).toEqual([`dynamodb:GetItem ${table}`, `dynamodb:PutItem ${table}`, `dynamodb:UpdateItem ${table}`, ...logs("webhook")].sort());
    expect(actions(policies.reader)).toEqual([
      `dynamodb:GetItem ${table}`, `dynamodb:UpdateItem ${table}`,
      "s3:GetObject arn:aws:s3:::chutchut-inbound-test/in/*", "s3:GetObjectTagging arn:aws:s3:::chutchut-inbound-test/in/*",
      "s3:PutObject arn:aws:s3:::chutchut-inbound-test/kept/*", "s3:PutObjectTagging arn:aws:s3:::chutchut-inbound-test/kept/*",
      "sns:Publish arn:aws:sns:eu-west-1:000000000000:chutchut-alerts", ...logs("reader"),
    ].sort());
    expect(actions(policies.stale)).toEqual([`dynamodb:Scan ${table}`, "sns:Publish arn:aws:sns:eu-west-1:000000000000:chutchut-alerts", ...logs("stale")].sort());
    expect(policies.lambda_trust.Statement[0].Principal).toEqual({ Service: "lambda.amazonaws.com" });
  });

  it("as tafs's provider: no kept/, the reader reads only the webhook's secret, the read API only its key, the table and in/", () => {
    const tafs = JSON.parse(execFileSync("bash", ["deploy/aws.sh", "policies"], {
      env: { ...process.env, CHUTCHUT_BUCKET: "chutchut-inbound-test", CHUTCHUT_MODE: "tafs", AWS_REGION: "eu-west-1", CHUTCHUT_RECIPIENTS: "support@kiff.test, billing@kiff.test" },
    }).toString());
    const actions = (p: { Statement: { Action: string | string[]; Resource: string }[] }) =>
      p.Statement.filter((s) => !String(s.Resource).includes(":logs:")).flatMap((s) => ([] as string[]).concat(s.Action).map((a) => `${a} ${s.Resource}`)).sort();
    const table = "arn:aws:dynamodb:eu-west-1:000000000000:table/chutchut-mail";
    expect(actions(tafs.reader)).toEqual([
      `dynamodb:GetItem ${table}`, `dynamodb:UpdateItem ${table}`, "sns:Publish arn:aws:sns:eu-west-1:000000000000:chutchut-alerts",
      "ssm:GetParameter arn:aws:ssm:eu-west-1:000000000000:parameter/chutchut/webhook-secret",
    ]);
    const send = tafs.provider.Statement.find((x: { Sid: string }) => x.Sid === "SendReplies");
    expect(send).toMatchObject({ Action: "ses:SendEmail", Resource: ["arn:aws:ses:eu-west-1:000000000000:identity/kiff.test"] });
    expect(actions({ Statement: tafs.provider.Statement.filter((x: { Sid: string }) => x.Sid !== "SendReplies") })).toEqual([
      `dynamodb:GetItem ${table}`, `dynamodb:UpdateItem ${table}`, "s3:GetObject arn:aws:s3:::chutchut-inbound-test/in/*",
      "ssm:GetParameter arn:aws:ssm:eu-west-1:000000000000:parameter/chutchut/read-key",
    ]);
    expect(policies).not.toHaveProperty("provider");
  });

  it("refuses tafs mode's settings that aren't tafs's webhook or SSM names, before calling AWS", () => {
    const run = (env: Record<string, string>) => spawnSync("bash", ["deploy/aws.sh", "up"], { env: {
      PATH: "/usr/bin:/bin", CHUTCHUT_BUCKET: "b", CHUTCHUT_RECIPIENTS: "kiff.test", CHUTCHUT_MODE: "tafs",
      CHUTCHUT_TAFS_WEBHOOK: "https://tafs.example.test/v1/doors/email", CHUTCHUT_WEBHOOK_SECRET_PARAM: "/c/s", CHUTCHUT_READ_KEY_PARAM: "/c/k", ...env,
    } }).status;
    expect(run({ CHUTCHUT_TAFS_WEBHOOK: "http://tafs.example.test/v1/doors/email" })).toBe(2);
    expect(run({ CHUTCHUT_TAFS_WEBHOOK: "https://tafs.example.test/elsewhere" })).toBe(2);
    expect(run({ CHUTCHUT_READ_KEY_PARAM: "c/k" })).toBe(2);
    expect(run({ CHUTCHUT_MODE: "other" })).toBe(2);
  });

  it("sends the reader GuardDuty's scan results for this bucket only", () => {
    expect(policies.scan_rule).toEqual({
      source: ["aws.guardduty"], "detail-type": ["GuardDuty Malware Protection Object Scan Result"],
      detail: { s3ObjectDetails: { bucketName: ["chutchut-inbound-test"] } },
    });
  });

  it("refuses a paired sender that isn't an address, and asks for the build, before calling AWS", () => {
    const run = (env: Record<string, string>) =>
      spawnSync("bash", ["deploy/aws.sh", "up"], { env: { PATH: "/usr/bin:/bin", CHUTCHUT_BUCKET: "b", CHUTCHUT_RECIPIENTS: "kiff.test", ...env } }).status;
    expect(run({ CHUTCHUT_PAIRED: 'a"b@example.test', CHUTCHUT_DIST: "/nonexistent" })).toBe(2);
    expect(run({ CHUTCHUT_PAIRED: "ana@example.test", CHUTCHUT_DIST: "/nonexistent" })).toBe(2);
  });

  it("asks for a bucket and refuses an unknown mode", () => {
    expect(() => execFileSync("bash", ["deploy/aws.sh", "policies"], { env: { PATH: process.env.PATH }, stdio: "pipe" })).toThrow();
    expect(() => execFileSync("bash", ["deploy/aws.sh", "down"], { env: { PATH: process.env.PATH, CHUTCHUT_BUCKET: "b" }, stdio: "pipe" })).toThrow();
  });

  // `up` against a stand-in for the aws command (never AWS itself): a failure inside $(topic) must stop the run, so
  // inherit_errexit can't be dropped without this going red. It needs bash 4.4 or later, as `up` does.
  const modern = spawnSync("bash", ["-c", "shopt -s inherit_errexit"]).status === 0;
  function upWithStub(failOn: string): { status: number | null; out: string } {
    const dir = mkdtempSync(join(tmpdir(), "chutchut-aws-"));
    writeFileSync(join(dir, "aws"), `#!/usr/bin/env bash
args="$*"
case "$args" in
  *"${failOn}"*) echo "stub refused: ${failOn}" >&2; exit 1 ;;
  *"sts get-caller-identity"*) echo 000000000000 ;;
  *"kms describe-key"*) echo key-1 ;;
  *"sns create-topic"*) echo arn:aws:sns:eu-west-1:000000000000:chutchut-inbound ;;
  *"iam get-role"*"Role.Arn"*) echo arn:aws:iam::000000000000:role/chutchut-malware-scan ;;
  *"describe-time-to-live"*) echo ENABLED ;;
esac
exit 0
`);
    chmodSync(join(dir, "aws"), 0o755);
    // Stand-in built functions, so the stand-in run needs no build.
    for (const f of ["webhook", "reader", "stale", "provider"]) writeFileSync(join(dir, `${f}.mjs`), "export const handler = () => {};\n");
    const run = spawnSync("bash", ["deploy/aws.sh", "up"], {
      env: {
        PATH: `${dir}:${process.env.PATH}`, CHUTCHUT_BUCKET: "chutchut-inbound-test", CHUTCHUT_RECIPIENTS: "support@example.test",
        CHUTCHUT_DIST: dir, CHUTCHUT_PAIRED: "ana@example.test",
      },
    });
    return { status: run.status, out: run.stdout.toString() };
  }

  it.skipIf(!modern)("runs to the end when every call succeeds (against a stand-in, never AWS)", () => {
    const run = upWithStub("never-matches");
    expect(run.status).toBe(0);
    expect(run.out).toContain("chutchut inbound: bucket chutchut-inbound-test");
  });

  it.skipIf(!modern)("stops, and never reports success, when a call inside $(topic) or the table's setup fails", () => {
    for (const failOn of ["SignatureVersion", "KmsMasterKeyId", "put-key-policy", "--attribute-name Policy", "update-continuous-backups"]) {
      const run = upWithStub(failOn);
      expect(run.status, failOn).not.toBe(0);
      expect(run.out, failOn).not.toContain("chutchut inbound:");
    }
  });
});
