import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";

// A secret from SSM Parameter Store (SecureString), read once per cold start: never in the code, the repo or the
// function's settings, which name only the parameter.
const cache = new Map<string, string>();

export async function secret(region: string, name: string): Promise<string> {
  const known = cache.get(name);
  if (known !== undefined) return known;
  const out = await new SSMClient({ region }).send(new GetParameterCommand({ Name: name, WithDecryption: true }));
  const value = out.Parameter?.Value;
  if (value === undefined || value === "") throw new Error(`${name} is empty`);
  cache.set(name, value);
  return value;
}
