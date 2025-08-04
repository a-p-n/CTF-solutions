import * as crypto from "crypto";
import {
  RequestLike,
  ResponseLike,
  Component,
} from "../web-bot-auth/packages/http-message-sig/src";

export interface SignedRequest extends RequestLike {
  body: string;
  headers: Record<string, string>;
}

export interface SignedResponse extends ResponseLike {
  body: string;
  headers: Record<string, string>;
  requestSignature: string;
}

export interface KeyPair {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  keyId: string;
}

export function generateKeyPair(keyId: string = "alice-key"): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  return {
    keyId,
    privateKey: crypto.createPrivateKey(privateKey),
    publicKey: crypto.createPublicKey(publicKey),
  };
}

export function createSigner(keyPair: KeyPair) {
  return {
    keyid: keyPair.keyId,
    alg: "ed25519" as const,
    sign: async (data: string): Promise<Uint8Array> => {
      const signature = crypto.sign(
        null,
        Buffer.from(data, "utf8"),
        keyPair.privateKey,
      );
      return new Uint8Array(signature);
    },
  };
}

export const clientSignComponents: Component[] = [
  "@method",
  "@path",
  "@query",
  "@authority",
  "content-type",
  "content-digest",
  "date",
  "x-public-key",
];

export const serverSignComponents: Component[] = [
  "@status",
  "content-type",
  "content-digest",
  "date",
  "request-signature",
];

export function parseBody(body: string) {
  const data = JSON.parse(body);
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("Expected object");
  }

  const keys = Object.keys(data);
  if (keys.length !== 1 || keys[0] !== "message") {
    throw new Error('Expected object with single key "message"');
  }

  if (typeof data.message !== "string") {
    throw new Error("Expected message to be a string");
  }

  return data.message;
}
