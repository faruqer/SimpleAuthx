const { createHash, createPublicKey, generateKeyPairSync } = require("crypto");

function normalizeMultiline(value) {
  if (!value) {
    return null;
  }
  return value.replace(/\\n/g, "\n");
}

function generateDevelopmentKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return {
    publicKey,
    privateKey,
  };
}

const envPrivateKey = normalizeMultiline(process.env.OAUTH_PRIVATE_KEY);
const envPublicKey = normalizeMultiline(process.env.OAUTH_PUBLIC_KEY);

const keyMaterial = envPrivateKey && envPublicKey
  ? { privateKey: envPrivateKey, publicKey: envPublicKey }
  : generateDevelopmentKeys();

const exportedJwk = createPublicKey(keyMaterial.publicKey).export({ format: "jwk" });
const defaultKid = createHash("sha256")
  .update(`${exportedJwk.n}.${exportedJwk.e}`)
  .digest("hex")
  .slice(0, 16);

const kid = process.env.OAUTH_KEY_ID || defaultKid;

function getJwks() {
  return {
    keys: [
      {
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        kid,
        n: exportedJwk.n,
        e: exportedJwk.e,
      },
    ],
  };
}

module.exports = {
  privateKey: keyMaterial.privateKey,
  publicKey: keyMaterial.publicKey,
  kid,
  getJwks,
};
