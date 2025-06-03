const express = require("express");
const jwt = require("jsonwebtoken");
const db = require("../db");
const { getTokenFromRequest } = require("../middleware/auth");
const config = require("../config");

const router = express.Router();

function parseRedirectUris(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch (_err) {
      return [];
    }
  }
  return [];
}

router.get("/authorize", async (req, res) => {
  try {
    const clientId = String(req.query.client_id || "").trim();
    const redirectUri = String(req.query.redirect_uri || "").trim();
    const responseType = String(req.query.response_type || "").trim();
    const state = String(req.query.state || "").trim();

    if (!clientId) {
      return res.status(400).json({ error: "client_id is required" });
    }

    if (!redirectUri) {
      return res.status(400).json({ error: "redirect_uri is required" });
    }

    if (responseType !== "code") {
      return res.status(400).json({ error: "response_type must be 'code'" });
    }

    if (!state) {
      return res.status(400).json({ error: "state is required" });
    }

    const client = await db("clients").select(["id", "client_id", "redirect_uris"]).where({ client_id: clientId }).first();
    if (!client) {
      return res.status(400).json({ error: "Invalid client_id" });
    }

    const allowedRedirectUris = parseRedirectUris(client.redirect_uris);
    if (!allowedRedirectUris.includes(redirectUri)) {
      return res.status(400).json({ error: "Invalid redirect_uri for this client" });
    }

    const token = getTokenFromRequest(req);
    if (!token) {
      return res.redirect(302, `/auth/login?next=${encodeURIComponent(req.originalUrl)}`);
    }

    try {
      jwt.verify(token, config.jwt.secret);
    } catch (_err) {
      return res.redirect(302, `/auth/login?next=${encodeURIComponent(req.originalUrl)}`);
    }

    return res.status(200).json({
      message: "Authorization request validated",
      next_step: "consent",
      request: {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType,
        state,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
