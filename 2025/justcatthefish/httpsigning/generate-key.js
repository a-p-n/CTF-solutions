#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  return {
    privateKey,
    publicKey
  };
}

const privateKeyPath = process.argv[2] || 'bob-private.pem';
const publicKeyPath = process.argv[3] || 'bob-public.pem';

const keyData = generateKeyPair();

fs.writeFileSync(privateKeyPath, keyData.privateKey);
fs.writeFileSync(publicKeyPath, keyData.publicKey);

console.log(`Generated Bob private key and saved to ${privateKeyPath}`);
console.log(`Generated Bob public key and saved to ${publicKeyPath}`);