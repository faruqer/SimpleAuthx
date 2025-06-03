const express = require("express");
const jwt = require("jsonwebtoken");
const db = require("../db");
const { getTokenFromRequest } = require("../middleware/auth");
const config = require("../config");

const router = express.Router();
const ALLOWED_SCOPES = new Set(["email", "profile"]);

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

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

function parseScopes(scopeValue) {
  const raw = String(scopeValue || "profile").trim();
  const requestedScopes = [...new Set(raw.split(/\s+/).filter(Boolean))];

  if (requestedScopes.length === 0) {
    return { error: "At least one scope is required" };
  }

  const invalidScope = requestedScopes.find((scope) => !ALLOWED_SCOPES.has(scope));
  if (invalidScope) {
    return { error: `Unsupported scope: ${invalidScope}` };
  }

  return { value: requestedScopes };
}

function buildRedirectUri(baseRedirectUri, params) {
  const redirect = new URL(baseRedirectUri);
  Object.entries(params).forEach(([key, value]) => {
    redirect.searchParams.set(key, String(value));
  });
  return redirect.toString();
}

async function validateAuthorizationRequest(req) {
  const clientId = String(req.query.client_id || req.body.client_id || "").trim();
  const redirectUri = String(req.query.redirect_uri || req.body.redirect_uri || "").trim();
  const responseType = String(req.query.response_type || req.body.response_type || "").trim();
  const state = String(req.query.state || req.body.state || "").trim();
  const scopeRaw = String(req.query.scope || req.body.scope || "profile").trim();

  if (!clientId) {
    return { error: "client_id is required", status: 400 };
  }

  if (!redirectUri) {
    return { error: "redirect_uri is required", status: 400 };
  }

  if (responseType !== "code") {
    return { error: "response_type must be 'code'", status: 400 };
  }

  if (!state) {
    return { error: "state is required", status: 400 };
  }

  const { value: scopes, error: scopeError } = parseScopes(scopeRaw);
  if (scopeError) {
    return { error: scopeError, status: 400 };
  }

  const client = await db("clients")
    .select(["id", "name", "client_id", "redirect_uris"])
    .where({ client_id: clientId })
    .first();

  if (!client) {
    return { error: "Invalid client_id", status: 400 };
  }

  const allowedRedirectUris = parseRedirectUris(client.redirect_uris);
  if (!allowedRedirectUris.includes(redirectUri)) {
    return { error: "Invalid redirect_uri for this client", status: 400 };
  }

  return {
    value: {
      client,
      clientId,
      redirectUri,
      responseType,
      state,
      scopes,
      scope: scopes.join(" "),
    },
  };
}

function getAuthenticatedUserId(req) {
  const token = getTokenFromRequest(req);
  if (!token) {
    return null;
  }

  try {
    const payload = jwt.verify(token, config.jwt.secret);
    return payload.sub;
  } catch (_err) {
    return null;
  }
}

router.get("/authorize", async (req, res) => {
  try {
    const validation = await validateAuthorizationRequest(req);
    if (validation.error) {
      return res.status(validation.status).json({ error: validation.error });
    }

    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.redirect(302, `/auth/login?next=${encodeURIComponent(req.originalUrl)}`);
    }

    const { clientId, redirectUri, responseType, state, scope } = validation.value;

    const consentUrl = new URL("/oauth/consent", `${req.protocol}://${req.get("host")}`);
    consentUrl.searchParams.set("client_id", clientId);
    consentUrl.searchParams.set("redirect_uri", redirectUri);
    consentUrl.searchParams.set("response_type", responseType);
    consentUrl.searchParams.set("state", state);
    consentUrl.searchParams.set("scope", scope);

    return res.redirect(302, consentUrl.pathname + consentUrl.search);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.get("/consent", async (req, res) => {
  try {
    const validation = await validateAuthorizationRequest(req);
    if (validation.error) {
      return res.status(validation.status).json({ error: validation.error });
    }

    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.redirect(302, `/auth/login?next=${encodeURIComponent(req.originalUrl)}`);
    }

    const { client, clientId, redirectUri, responseType, state, scope, scopes } = validation.value;
    const scopeListHtml = scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join("");

    return res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SimpleAuthx Consent</title>
  </head>
  <body style="font-family: Arial, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px;">
    <h1>Authorize ${escapeHtml(client.name)}</h1>
    <p>This app is requesting permission to access:</p>
    <ul>${scopeListHtml}</ul>
    <p><strong>Client ID:</strong> ${escapeHtml(clientId)}</p>

    <form method="post" action="/oauth/consent" style="display: inline-block; margin-right: 8px;">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}" />
      <input type="hidden" name="response_type" value="${escapeHtml(responseType)}" />
      <input type="hidden" name="state" value="${escapeHtml(state)}" />
      <input type="hidden" name="scope" value="${escapeHtml(scope)}" />
      <button type="submit" name="decision" value="approve">Approve</button>
    </form>

    <form method="post" action="/oauth/consent" style="display: inline-block;">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}" />
      <input type="hidden" name="response_type" value="${escapeHtml(responseType)}" />
      <input type="hidden" name="state" value="${escapeHtml(state)}" />
      <input type="hidden" name="scope" value="${escapeHtml(scope)}" />
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </body>
</html>`);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/consent", async (req, res) => {
  try {
    const validation = await validateAuthorizationRequest(req);
    if (validation.error) {
      return res.status(validation.status).json({ error: validation.error });
    }

    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      const next = `/oauth/consent?${new URLSearchParams({
        client_id: validation.value.clientId,
        redirect_uri: validation.value.redirectUri,
        response_type: validation.value.responseType,
        state: validation.value.state,
        scope: validation.value.scope,
      }).toString()}`;
      return res.redirect(302, `/auth/login?next=${encodeURIComponent(next)}`);
    }

    const decision = String(req.body.decision || "").trim().toLowerCase();
    const { client, redirectUri, state, scopes } = validation.value;

    if (decision === "deny") {
      const deniedRedirect = buildRedirectUri(redirectUri, {
        error: "access_denied",
        state,
      });
      return res.redirect(302, deniedRedirect);
    }

    if (decision !== "approve") {
      return res.status(400).json({ error: "decision must be approve or deny" });
    }

    const existingConsent = await db("user_consents")
      .select(["id", "scopes"])
      .where({ user_id: userId, client_id: client.id })
      .first();

    if (!existingConsent) {
      await db("user_consents").insert({
        user_id: userId,
        client_id: client.id,
        scopes,
        granted_at: db.fn.now(),
      });
    } else {
      const existingScopes = Array.isArray(existingConsent.scopes) ? existingConsent.scopes : [];
      const mergedScopes = [...new Set([...existingScopes, ...scopes])];

      await db("user_consents")
        .where({ id: existingConsent.id })
        .update({
          scopes: mergedScopes,
          granted_at: db.fn.now(),
          updated_at: db.fn.now(),
        });
    }

    const continueRedirect = buildRedirectUri(redirectUri, {
      state,
      consent: "approved",
    });

    return res.redirect(302, continueRedirect);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
