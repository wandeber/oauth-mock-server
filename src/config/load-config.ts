import fs from "node:fs";
import path from "node:path";

import { normalizeConfig } from "./normalize-config";
import type { JsonObject, NormalizedMockServerConfig } from "./types";

export interface RuntimeConfigLoadOptions {
  baseDir: string;
  configFilePath?: string;
  env: NodeJS.ProcessEnv;
  logger: Pick<Console, "error">;
  exitOnConfigError: boolean;
}

export function loadNormalizedConfig(options: RuntimeConfigLoadOptions): {
  config: NormalizedMockServerConfig;
  loadedConfigPath: string | null;
} {
  const configPath = resolveConfigPath({
    baseDir: options.baseDir,
    configFilePath: options.configFilePath,
    env: options.env
  });

  try {
    const fileConfig = loadJsonConfig(configPath, options);
    const config = normalizeConfig(fileConfig, options.env);
    return {
      config,
      loadedConfigPath: configPath
    };
  } catch (error) {
    return failOnConfigError(
      `[oauth-mock] Invalid configuration: ${getErrorMessage(error)}`,
      options.logger,
      options.exitOnConfigError
    );
  }
}

export function resolveConfigPath(options: {
  baseDir: string;
  configFilePath?: string;
  env: NodeJS.ProcessEnv;
}): string {
  if (options.configFilePath) {
    return path.resolve(options.configFilePath);
  }

  if (options.env.MOCK_OAUTH_CONFIG_FILE) {
    return path.resolve(process.cwd(), options.env.MOCK_OAUTH_CONFIG_FILE);
  }

  return path.join(options.baseDir, "mock-config.json");
}

export function loadJsonConfig(
  filePath: string,
  options: {
    logger: Pick<Console, "error">;
    exitOnConfigError: boolean;
  }
): JsonObject {
  if (!fs.existsSync(filePath)) {
    return failOnConfigError(
      `[oauth-mock] JSON config file not found: ${filePath}`,
      options.logger,
      options.exitOnConfigError
    );
  }

  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const json = JSON.parse(raw);
    return asObject(json);
  } catch (error) {
    const message = `[oauth-mock] Cannot parse JSON config ${filePath}: ${getErrorMessage(error)}`;
    return failOnConfigError(message, options.logger, options.exitOnConfigError);
  }
}

function failOnConfigError(
  message: string,
  logger: Pick<Console, "error">,
  exitOnConfigError: boolean
): never {
  logger.error(message);
  if (exitOnConfigError) {
    process.exit(1);
  }

  throw new Error(message);
}

function asObject(value: unknown): JsonObject {
  return isPlainObject(value) ? value : {};
}

function isPlainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
