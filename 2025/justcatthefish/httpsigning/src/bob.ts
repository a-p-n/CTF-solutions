import * as http from "http";
import * as crypto from "crypto";
import * as fs from "fs";

import {
  generateKeyPair,
  createSigner,
  KeyPair,
  SignedRequest,
  SignedResponse,
  serverSignComponents,
  parseBody,
} from "./utils";
import {
  signatureHeaders,
  verify,
  RequestLike,
  ResponseLike,
  Parameters,
  Component,
} from "../web-bot-auth/packages/http-message-sig/src";

class BobServer {
  private server: http.Server;
  private keyPair: KeyPair;
  private signer: any;
  private port: number;

  constructor(port: number, privateKeyPath: string) {
    this.port = port;
    this.keyPair = this.loadKeyPair(privateKeyPath);
    this.signer = createSigner(this.keyPair);
    this.server = http.createServer((req, res) => this.handleRequest(req, res));
  }

  private loadKeyPair(privateKeyPath: string): KeyPair {
    try {
      const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
      const privateKey = crypto.createPrivateKey(privateKeyPem);
      const publicKey = crypto.createPublicKey(privateKey);

      return {
        keyId: "bob-server",
        privateKey,
        publicKey,
      };
    } catch (error) {
      throw new Error(
        `Failed to load private key from ${privateKeyPath}: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  private extractClientPublicKey(
    headers: Record<string, string>,
  ): crypto.KeyObject | null {
    try {
      const publicKeyHeader = headers["x-public-key"];
      if (!publicKeyHeader) {
        return null;
      }

      const publicKeyPem = Buffer.from(publicKeyHeader, "base64").toString(
        "utf8",
      );
      return crypto.createPublicKey(publicKeyPem);
    } catch (error) {
      return null;
    }
  }

  private async verifyRequestSignature(
    request: SignedRequest,
    clientPublicKey: crypto.KeyObject,
  ): Promise<boolean> {
    try {
      const verifier = async (
        data: string,
        signature: Uint8Array,
        params: Parameters,
        components?: Component[],
      ) => {
        if (params.alg !== "ed25519") {
          return false;
        }
        try {
          return crypto.verify(
            null,
            Buffer.from(data, "utf8"),
            clientPublicKey,
            Buffer.from(signature),
          );
        } catch {
          return false;
        }
      };

      return await verify(request, verifier);
    } catch (error) {
      return false;
    }
  }

  private async createSignedResponse(
    status: number,
    body: string,
    requestSignature?: string,
  ): Promise<SignedResponse> {
    const responseHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body).toString(),
      Date: new Date().toUTCString(),
    };

    const bodyHash = crypto.createHash("sha256").update(body).digest("base64");
    responseHeaders["Content-Digest"] = `sha-256=:${bodyHash}:`;

    if (requestSignature) {
      responseHeaders["Request-Signature"] = requestSignature;
    } else {
      responseHeaders["Request-Signature"] = "null";
    }

    const response: ResponseLike = {
      status,
      headers: responseHeaders,
    };

    const sigHeaders = await signatureHeaders(response, {
      signer: this.signer,
      components: serverSignComponents,
    });

    return {
      ...response,
      body,
      headers: {
        ...responseHeaders,
        Signature: sigHeaders.Signature,
        "Signature-Input": sigHeaders["Signature-Input"],
      },
      requestSignature: responseHeaders["Request-Signature"],
    };
  }

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("error", (error) => {
      console.error(`${new Date().toISOString()} - Request error:`, error);
      res.writeHead(400);
      res.end("Bad Request");
    });

    req.on("end", async () => {
      try {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);

        const aliceRequest: SignedRequest = {
          method: req.method || "GET",
          url: `http://${req.headers.host}${req.url}`,
          headers: req.headers as Record<string, string>,
          body,
        };

        const validationResult = await this.validateRequest(aliceRequest);
        if (!validationResult.valid) {
          await this.sendErrorResponse(
            res,
            validationResult.status,
            validationResult.error,
            validationResult.message,
          );
          return;
        }

        const msg = parseBody(aliceRequest.body);

        let response = "True.";
        if (msg === "The truth is out there.") {
          response = "False.";
        }

        const successResponse = await this.createSignedResponse(
          200,
          JSON.stringify({
            message: response,
          }),
          aliceRequest.headers["signature"],
        );

        this.sendResponse(res, successResponse);
        console.log(
          `${new Date().toISOString()} - Response sent with signature`,
        );
      } catch (error) {
        console.error(`${new Date().toISOString()} - Error:`, error);
        await this.sendErrorResponse(
          res,
          500,
          "Internal server error",
          error instanceof Error ? error.message : "Unknown error",
        );
      }
    });
  }

  private async validateRequest(request: SignedRequest): Promise<{
    valid: boolean;
    status?: number;
    error?: string;
    message?: string;
  }> {
    const reqBodyHash = crypto
      .createHash("sha256")
      .update(request.body)
      .digest("base64");
    const requestContentDigest = request.headers["content-digest"];

    if (requestContentDigest !== `sha-256=:${reqBodyHash}:`) {
      return {
        valid: false,
        status: 400,
        error: "Invalid body hash",
        message: "Client must provide valid Content-Digest header",
      };
    }

    const clientPublicKey = this.extractClientPublicKey(request.headers);
    if (clientPublicKey == null) {
      return {
        valid: false,
        status: 400,
        error: "Missing or invalid X-Public-Key header",
        message: "Client must provide public key in X-Public-Key header",
      };
    }

    const isSignatureValid = await this.verifyRequestSignature(
      request,
      clientPublicKey,
    );
    if (isSignatureValid !== true) {
      return {
        valid: false,
        status: 401,
        error: "Invalid signature",
        message: "Request signature verification failed",
      };
    }

    return { valid: true };
  }

  private async sendErrorResponse(
    res: http.ServerResponse,
    status: number,
    error: string,
    message: string,
  ): Promise<void> {
    try {
      const errorResponse = await this.createSignedResponse(
        status,
        JSON.stringify({ error, message }),
      );
      this.sendResponse(res, errorResponse);
    } catch (responseError) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to create error response" }));
    }
  }

  private sendResponse(
    res: http.ServerResponse,
    response: SignedResponse,
  ): void {
    res.writeHead(response.status, response.headers);
    res.end(response.body);
  }

  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.on("error", reject);

      this.server.listen(this.port, () => {
        console.log(`Bob HTTP server listening on port ${this.port}`);
        console.log(`Key ID: ${this.keyPair.keyId}`);
        resolve();
      });
    });
  }

  public stop(): void {
    this.server.close();
  }
}

export async function main(): Promise<void> {
  const port = parseInt(process.env.PORT) || 8080;
  const privateKeyPath = process.env.BOB_PRIVATE_KEY_PATH || "bob-private.pem";
  const server = new BobServer(port, privateKeyPath);

  try {
    await server.start();

    process.on("SIGINT", () => {
      console.log("\nShutting down Bob server...");
      server.stop();
      process.exit(0);
    });

    process.on("SIGTERM", () => {
      console.log("\nShutting down Bob server...");
      server.stop();
      process.exit(0);
    });
  } catch (error) {
    console.error("Failed to start Bob server:", error);
    process.exit(1);
  }
}

export { BobServer };

if (require.main === module) {
  main().catch(console.error);
}
