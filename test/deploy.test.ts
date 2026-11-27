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
esac
exit 0
`);
    chmodSync(join(dir, "aws"), 0o755);
    const run = spawnSync("bash", ["deploy/aws.sh", "up"], {
      env: { PATH: `${dir}:${process.env.PATH}`, CHUTCHUT_BUCKET: "chutchut-inbound-test", CHUTCHUT_RECIPIENTS: "support@example.test" },
    });
    return { status: run.status, out: run.stdout.toString() };
  }

  it.skipIf(!modern)("runs to the end when every call succeeds (against a stand-in, never AWS)", () => {
    const run = upWithStub("never-matches");
    expect(run.status).toBe(0);
    expect(run.out).toContain("chutchut inbound: bucket chutchut-inbound-test");
  });

  it.skipIf(!modern)("stops, and never reports success, when a call inside $(topic) fails", () => {
    for (const failOn of ["SignatureVersion", "KmsMasterKeyId", "put-key-policy", "--attribute-name Policy"]) {
      const run = upWithStub(failOn);
      expect(run.status, failOn).not.toBe(0);
      expect(run.out, failOn).not.toContain("chutchut inbound:");
    }
  });
});
