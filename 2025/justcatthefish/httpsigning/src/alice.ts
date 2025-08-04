import * as crypto from "crypto";
import * as fs from "fs";
import {
  signatureHeaders,
  verify,
  RequestLike,
  ResponseLike,
  Component,
  Parameters,
} from "../web-bot-auth/packages/http-message-sig/src";
import {
  generateKeyPair,
  createSigner,
  KeyPair,
  SignedRequest,
  SignedResponse,
  clientSignComponents,
  serverSignComponents,
  parseBody,
} from "./utils";
import * as readline from "readline";
import { ProxyAgent } from "undici";
import { FLAG } from "./flag";

export async function sendRequest(
  url: string,
  body: string,
  keyPair: KeyPair,
  method: string = "POST",
  proxy?: string,
): Promise<SignedResponse> {
  const parsedUrl = new URL(url);
  const signer = createSigner(keyPair);

  const publicKeyPem = keyPair.publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;

  const request: RequestLike = {
    method: method.toUpperCase(),
    url: url,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body).toString(),
      Date: new Date().toUTCString(),
      Host: parsedUrl.host,
      "X-Public-Key": Buffer.from(publicKeyPem).toString("base64"),
    },
  };

  const bodyHash = crypto.createHash("sha256").update(body).digest("base64");
  request.headers["Content-Digest"] = `sha-256=:${bodyHash}:`;

  const sigHeaders = await signatureHeaders(request, {
    signer,
    components: clientSignComponents,
    created: new Date(),
  });

  const signedRequest: SignedRequest = {
    ...request,
    body,
    headers: {
      ...(request.headers as Record<string, string>),
      Signature: sigHeaders.Signature,
      "Signature-Input": sigHeaders["Signature-Input"],
    },
  };

  const fetchOptions: any = {
    method: signedRequest.method,
    headers: signedRequest.headers,
    body: signedRequest.body,
  };

  if (proxy) {
    fetchOptions.dispatcher = new ProxyAgent(proxy);
    console.log(`Using proxy: ${proxy}`);
  }

  const response = await fetch(url, fetchOptions);
  const responseBody = await response.text();

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return {
    status: response.status,
    headers,
    body: responseBody,
    requestSignature: signedRequest.headers["Signature"],
  };
}

export async function processResponse(
  response: SignedResponse,
  bobPublicKey: crypto.KeyObject,
) {
  if (!response.headers["content-digest"]) {
    throw new Error("No content-digest header");
  }

  const responseBodyHash = crypto
    .createHash("sha256")
    .update(response.body)
    .digest("base64");
  const responseContentDigest = response.headers["content-digest"];

  if (responseContentDigest !== `sha-256=:${responseBodyHash}:`) {
    throw new Error("Wrong response body digest");
  }

  if (!response.headers["signature"] || !response.headers["signature-input"]) {
    throw new Error("Missing signature or signature-input header");
  }

  const verifier = async (
    data: string,
    signature: Uint8Array,
    params: Parameters,
    components?: Component[],
  ) => {
    if (response.headers["request-signature"] !== response.requestSignature) {
      throw new Error("Wong request-signature");
    }

    if (params.keyid !== "bob-server" || params.alg !== "ed25519") {
      throw new Error("Wrong params");
    }

    if (
      !components ||
      JSON.stringify(components) !== JSON.stringify(serverSignComponents)
    ) {
      throw new Error("Wrong signature-input");
    }

    const result = crypto.verify(
      null,
      Buffer.from(data, "utf8"),
      bobPublicKey,
      Buffer.from(signature),
    );
    if (result !== true) {
      throw new Error("Verification failed");
    }
  };

  await verify(response, verifier);
}

export async function main(): Promise<void> {
  const publicKeyPath = process.env.BOB_PUBLIC_KEY_PATH || "bob-public.pem";
  const bobUrl = process.env.BOB_URL || "http://localhost:8080";

  let bobPublicKey: crypto.KeyObject;
  try {
    const publicKeyPem = fs.readFileSync(publicKeyPath, "utf8");
    bobPublicKey = crypto.createPublicKey(publicKeyPem);
  } catch (error) {
    console.error(
      `Failed to load Bob's public key from ${publicKeyPath}:`,
      error instanceof Error ? error.message : "Unknown error",
    );
    return;
  }

  const keyPair = generateKeyPair("alice-key");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const proxy = await new Promise<string>((resolve) => {
    rl.question("Enter proxy (or press enter to skip): ", (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });

  if (proxy && !proxy.startsWith("http://")) {
    console.error(`Invalid proxy value ${proxy}`);
    return;
  }

  const body = JSON.stringify({
    message:
      "Extraterrestrial intelligent beings do not exist and evolution is real.",
  });

  try {
    const response = await sendRequest(bobUrl, body, keyPair, "POST", proxy);
    await processResponse(response, bobPublicKey);

    const msg = parseBody(response.body);
    if (msg === "False.") {
      console.log(FLAG);
    } else {
      console.log(msg);
    }
    console.log(":*");
  } catch (error) {
    console.error("Request failed");
  }
}

if (require.main === module) {
  main()
    .catch(console.error)
    .finally(() => process.exit(0));
}
