import type { IncomingMessage } from "node:http";
import { URLSearchParams } from "node:url";

import type { JsonObject } from "../config/types";
import { MAX_REQUEST_BODY_LENGTH } from "../oauth/constants";

export function parseBody(req: IncomingMessage, body: string): Record<string, string> {
  const contentTypeHeader = req.headers["content-type"];
  const contentType = Array.isArray(contentTypeHeader)
    ? contentTypeHeader.join(";")
    : contentTypeHeader ?? "";

  // The mock accepts either JSON or classic form posts so it can interoperate
  // with a wider range of local clients without leaking transport details into
  // the domain services.
  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(body || "{}");
      return toStringRecord(asObject(parsed));
    } catch {
      return {};
    }
  }

  const params = new URLSearchParams(body);
  const parsed: Record<string, string> = {};
  for (const [key, value] of params.entries()) {
    parsed[key] = value;
  }

  return parsed;
}

export function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    req.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_REQUEST_BODY_LENGTH) {
        reject(new Error("Request too large"));
      }
    });
    req.on("end", () => resolve(buffer));
    req.on("error", reject);
  });
}

function toStringRecord(value: JsonObject): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, entryValue] of Object.entries(value)) {
    output[key] = String(entryValue);
  }
  return output;
}

function asObject(value: unknown): JsonObject {
  return isPlainObject(value) ? value : {};
}

function isPlainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
