import crypto from "node:crypto";

export function issueOpaqueToken(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(32).toString("base64url")}`;
}
