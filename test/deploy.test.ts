import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

// The policies deploy/aws.sh sets, read with no AWS access (its `policies` mode, a made-up account).
const policies = JSON.parse(
  execFileSync("bash", ["deploy/aws.sh", "policies"], { env: { ...process.env, LOGE_BUCKET: "loge-inbound-test", AWS_REGION: "eu-west-1" } }).toString(),
);
const rule = "arn:aws:ses:eu-west-1:000000000000:receipt-rule-set/loge:receipt-rule/loge-inbound";

describe("deploy", () => {
  it("lets only SES write to the bucket, only under in/, only for this account's own rule", () => {
    const allow = policies.bucket.Statement.filter((s: { Effect: string }) => s.Effect === "Allow");
    expect(allow).toHaveLength(1);
    expect(allow[0]).toMatchObject({
      Principal: { Service: "ses.amazonaws.com" }, Action: "s3:PutObject", Resource: "arn:aws:s3:::loge-inbound-test/in/*",
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
    expect(objects.Resource).toBe("arn:aws:s3:::loge-inbound-test/in/*");
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
        execFileSync("bash", ["deploy/aws.sh", "up"], { env: { PATH: "/usr/bin:/bin", LOGE_BUCKET: "b", LOGE_RECIPIENTS: bad }, stdio: "pipe" });
      } catch (e) {
        code = (e as { status: number }).status;
      }
      expect(code, bad).toBe(2);
    }
  });

  it("asks for a bucket and refuses an unknown mode", () => {
    expect(() => execFileSync("bash", ["deploy/aws.sh", "policies"], { env: { PATH: process.env.PATH }, stdio: "pipe" })).toThrow();
    expect(() => execFileSync("bash", ["deploy/aws.sh", "down"], { env: { PATH: process.env.PATH, LOGE_BUCKET: "b" }, stdio: "pipe" })).toThrow();
  });
});
