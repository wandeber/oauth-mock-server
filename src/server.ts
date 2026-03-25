import http, { type Server } from "node:http";

import { loadNormalizedConfig } from "./config/load-config";
import type { NormalizedMockServerConfig } from "./config/types";
import { buildIssuerUrl } from "./oauth/metadata";
import { createRouter } from "./http/router";
import { createInMemoryOauthStores } from "./storage/in-memory-store";

export interface RuntimeOptions {
  baseDir?: string;
  configFilePath?: string;
  env?: NodeJS.ProcessEnv;
  exitOnConfigError?: boolean;
  logger?: Pick<Console, "log" | "error">;
}

export interface OauthMockServer {
  config: NormalizedMockServerConfig;
  server: Server;
  loadedConfigPath: string | null;
  start: () => Promise<void>;
  stop: () => Promise<void>;
}

export function createOauthMockServer(options: RuntimeOptions = {}): OauthMockServer {
  const env = options.env ?? process.env;
  const baseDir = options.baseDir ?? process.cwd();
  const logger = options.logger ?? console;
  const exitOnConfigError = options.exitOnConfigError ?? false;

  const { config, loadedConfigPath } = loadNormalizedConfig({
    baseDir,
    configFilePath: options.configFilePath,
    env,
    logger,
    exitOnConfigError
  });

  const stores = createInMemoryOauthStores();
  const server = http.createServer(createRouter({ config, stores }));

  return {
    config,
    server,
    loadedConfigPath,
    start: () => startServer(server, config.server.port),
    stop: () => stopServer(server)
  };
}

function startServer(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("error", onError);
      reject(error);
    };
    server.once("error", onError);
    server.listen(port, () => {
      server.off("error", onError);
      resolve();
    });
  });
}

function stopServer(server: Server): Promise<void> {
  if (!server.listening) {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function runCli(): Promise<void> {
  const app = createOauthMockServer({ exitOnConfigError: true });
  await app.start();

  console.log(`[oauth-mock] listening on ${app.config.server.issuer}`);
  console.log(`[oauth-mock] loaded JSON config: ${app.loadedConfigPath ?? "none"}`);
  console.log(`[oauth-mock] registered clients: ${Object.keys(app.config.clients).join(", ")}`);
  console.log(`[oauth-mock] JWKS endpoint: ${buildIssuerUrl(app.config.server.issuer, "/jwks")}`);
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

if (require.main === module) {
  runCli().catch((error: unknown) => {
    console.error(`[oauth-mock] Cannot start server: ${getErrorMessage(error)}`);
    process.exit(1);
  });
}
