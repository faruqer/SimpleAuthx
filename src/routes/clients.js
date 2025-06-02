const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const db = require("../db");

const router = express.Router();
const CLIENT_SECRET_ROUNDS = 12;

function generateClientId() {
  return `sax_${crypto.randomBytes(24).toString("hex")}`;
}

function generateClientSecret() {
  return `sax_secret_${crypto.randomBytes(32).toString("base64url")}`;
}

function isValidRedirectUri(uri) {
  try {
    const parsed = new URL(uri);
    const isHttps = parsed.protocol === "https:";
    const isLocalhostHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1"].includes(parsed.hostname);
    return isHttps || isLocalhostHttp;
  } catch (_err) {
    return false;
  }
}

function parseAndValidateRedirectUris(input) {
  if (!Array.isArray(input) || input.length === 0) {
    return { error: "redirect_uris must be a non-empty array" };
  }

  const normalized = input
    .map((uri) => String(uri || "").trim())
    .filter((uri) => uri.length > 0);

  if (normalized.length === 0) {
    return { error: "At least one valid redirect URI is required" };
  }

  const invalid = normalized.find((uri) => !isValidRedirectUri(uri));
  if (invalid) {
    return {
      error:
        "Each redirect URI must be an absolute URL with https, or http only for localhost/127.0.0.1",
    };
  }

  const unique = [...new Set(normalized)];
  return { value: unique };
}

router.post("/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const { value: redirectUris, error } = parseAndValidateRedirectUris(req.body.redirect_uris);

    if (!name) {
      return res.status(400).json({ error: "name is required" });
    }

    if (error) {
      return res.status(400).json({ error });
    }

    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    const clientSecretHash = await bcrypt.hash(clientSecret, CLIENT_SECRET_ROUNDS);

    const [createdClient] = await db("clients")
      .insert({
        name,
        client_id: clientId,
        client_secret_hash: clientSecretHash,
        redirect_uris: redirectUris,
      })
      .returning(["id", "name", "client_id", "redirect_uris", "created_at"]);

    return res.status(201).json({
      client: createdClient,
      credentials: {
        client_id: clientId,
        client_secret: clientSecret,
      },
      note: "Store client_secret securely. It will not be shown again.",
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const client = await db("clients")
      .select(["id", "name", "client_id", "redirect_uris", "created_at", "updated_at"])
      .where({ id: req.params.id })
      .first();

    if (!client) {
      return res.status(404).json({ error: "Client not found" });
    }

    return res.json({ client });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
