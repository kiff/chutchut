import { describe, expect, it } from "vitest";
import { config } from "../src/config.js";

const env = {
  AWS_REGION: "eu-west-1", CHUTCHUT_BUCKET: "b", CHUTCHUT_TABLE: "t",
  CHUTCHUT_TOPIC_ARN: "arn:aws:sns:eu-west-1:000000000000:chutchut-inbound",
  CHUTCHUT_ALERTS_ARN: "arn:aws:sns:eu-west-1:000000000000:chutchut-alerts",
  CHUTCHUT_PAIRED: " Ana@Example.test , ,bob@example.test",
};

describe("config", () => {
  it("reads every setting, the paired senders keyed as the door keys them, and the Solo plan's limits by default", () => {
    const c = config(env);
    expect([...c.paired]).toEqual(["ana@example.test", "bob@example.test"]);
    expect(c.limits).toEqual({ inboundPerDay: 100, knocksPerSender: 1, knocksPerDomain: 10, knocksPerDay: 50 });
    expect(config({ ...env, CHUTCHUT_INBOUND_PER_DAY: "500" }).limits.inboundPerDay).toBe(500);
  });

  it("fails at start on a missing or malformed setting, before any mail", () => {
    for (const name of ["AWS_REGION", "CHUTCHUT_BUCKET", "CHUTCHUT_TABLE", "CHUTCHUT_TOPIC_ARN", "CHUTCHUT_ALERTS_ARN"]) {
      expect(() => config({ ...env, [name]: "" }), name).toThrow();
    }
    expect(() => config({ ...env, CHUTCHUT_TOPIC_ARN: "chutchut-inbound" })).toThrow();
    expect(() => config({ ...env, CHUTCHUT_INBOUND_PER_DAY: "-1" })).toThrow();
    expect(() => config({ ...env, CHUTCHUT_KNOCKS_PER_DAY: "lots" })).toThrow();
  });

  it("pairs no one when none is set, so every sender knocks", () => {
    expect(config({ ...env, CHUTCHUT_PAIRED: undefined }).paired.size).toBe(0);
  });
});
