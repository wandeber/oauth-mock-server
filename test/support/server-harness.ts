import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { createOauthMockServer } from "../../src/server";
import { PROJECT_DIR } from "./constants";

type OauthMockServer = ReturnType<typeof createOauthMockServer>;

export interface OauthTestServerHandle {
  baseUrl: string;
  app: OauthMockServer;
  configFilePath: string;
  stop: () => Promise<void>;
}

async function getAvailablePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();

    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close(() => reject(new Error("Cannot allocate a free port")));
        return;
      }

      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}

export async function withOauthMockServer(
  config: unknown,
  test: (handle: OauthTestServerHandle) => Promise<void>
): Promise<void> {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "oauth-mock-test-"));
  const configFilePath = path.join(tempDir, "mock-config.json");
  fs.writeFileSync(configFilePath, `${JSON.stringify(config, null, 2)}\n`, "utf8");

  const port = await getAvailablePort();
  const app = createOauthMockServer({
    baseDir: PROJECT_DIR,
    configFilePath,
    env: {
      PORT: String(port)
    },
    exitOnConfigError: true,
    logger: {
      log() {
        // Keep test output quiet unless a failure bubbles up.
      },
      error() {
        // The helper intentionally silences config noise to keep assertions readable.
      }
    }
  });

  try {
    await app.start();

    const handle: OauthTestServerHandle = {
      app,
      baseUrl: `http://localhost:${port}`,
      configFilePath,
      stop: async () => {
        await app.stop();
      }
    };

    await test(handle);
  } finally {
    try {
      await app.stop();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}
