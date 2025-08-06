const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const db = require("../db");
const { getTokenFromRequest, parseCookies } = require("../middleware/auth");
const config = require("../config");
const oauthKeys = require("../security/oauth-keys");

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

function parseState(stateValue) {
  const state = String(stateValue || "").trim();
  if (!state) {
    return { error: "state is required" };
  }
  if (state.length < 8 || state.length > 512) {
    return { error: "state length must be between 8 and 512" };
  }
  return { value: state };
}

function buildRedirectUri(baseRedirectUri, params) {
  const redirect = new URL(baseRedirectUri);
  Object.entries(params).forEach(([key, value]) => {
    redirect.searchParams.set(key, String(value));
  });
  return redirect.toString();
}

function generateAuthorizationCode() {
  return crypto.randomBytes(32).toString("base64url");
}

function createCsrfToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function expiresInSeconds(seconds) {
  const date = new Date();
  date.setSeconds(date.getSeconds() + seconds);
  return date;
}

function sendTokenError(res, statusCode, error, errorDescription) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  return res.status(statusCode).json({
    error,
    error_description: errorDescription,
  });
}

function sendUserInfoInvalidToken(res, errorDescription) {
  res.setHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="${errorDescription}"`);
  return res.status(401).json({
    error: "invalid_token",
    error_description: errorDescription,
  });
}

function sendAuthorizeError(res, redirectUri, state, error, errorDescription) {
  if (!redirectUri) {
    return res.status(400).json({
      error,
      error_description: errorDescription,
    });
  }

  const redirect = buildRedirectUri(redirectUri, {
    error,
    error_description: errorDescription,
    ...(state ? { state } : {}),
  });
  return res.redirect(302, redirect);
}

function getBearerToken(req) {
  const authHeader = String(req.headers.authorization || "");
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }
  return authHeader.slice(7);
}

function toScopeArray(scopes) {
  if (Array.isArray(scopes)) {
    return scopes;
  }
  if (typeof scopes === "string") {
    try {
      const parsed = JSON.parse(scopes);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    } catch (_err) {
      return scopes.split(/\s+/).filter(Boolean);
    }
  }
  return [];
}

function setConsentCsrfCookie(res, csrfToken) {
  res.cookie("simpleauthx_oauth_csrf", csrfToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: config.security.enforceHttps,
    path: "/oauth",
    maxAge: 10 * 60 * 1000,
  });
}

function clearConsentCsrfCookie(res) {
  res.clearCookie("simpleauthx_oauth_csrf", {
    path: "/oauth",
  });
}

function validateConsentCsrf(req) {
  const csrfTokenFromBody = String(req.body.csrf_token || "");
  const cookies = parseCookies(req);
  const csrfTokenFromCookie = String(cookies.simpleauthx_oauth_csrf || "");
  if (!csrfTokenFromBody || !csrfTokenFromCookie) {
    return false;
  }
  return csrfTokenFromBody === csrfTokenFromCookie;
}

async function validateAuthorizationRequest(req) {
  const clientId = String(req.query.client_id || req.body.client_id || "").trim();
  const redirectUri = String(req.query.redirect_uri || req.body.redirect_uri || "").trim();
  const responseType = String(req.query.response_type || req.body.response_type || "").trim();
  const rawState = String(req.query.state || req.body.state || "").trim();
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

  const { value: state, error: stateError } = parseState(rawState);
  if (stateError) {
    return { error: stateError, status: 400 };
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
      return res.status(validation.status).json({
        error: "invalid_request",
        error_description: validation.error,
      });
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
    const csrfToken = createCsrfToken();
    setConsentCsrfCookie(res, csrfToken);
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
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
      <button type="submit" name="decision" value="approve">Approve</button>
    </form>

    <form method="post" action="/oauth/consent" style="display: inline-block;">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}" />
      <input type="hidden" name="response_type" value="${escapeHtml(responseType)}" />
      <input type="hidden" name="state" value="${escapeHtml(state)}" />
      <input type="hidden" name="scope" value="${escapeHtml(scope)}" />
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
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

    if (!validateConsentCsrf(req)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid CSRF token",
      });
    }

    const decision = String(req.body.decision || "").trim().toLowerCase();
    const { client, redirectUri, state, scopes } = validation.value;

    if (decision === "deny") {
      clearConsentCsrfCookie(res);
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

    const authorizationCode = generateAuthorizationCode();

    await db("auth_codes").insert({
      code: authorizationCode,
      user_id: userId,
      client_id: client.id,
      redirect_uri: redirectUri,
      scopes,
      expires_at: expiresInSeconds(config.oauth.authCodeExpiresInSeconds),
      is_used: false,
    });

    clearConsentCsrfCookie(res);

    const continueRedirect = buildRedirectUri(redirectUri, {
      code: authorizationCode,
      state,
    });

    return res.redirect(302, continueRedirect);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/token", async (req, res) => {
  const grantType = String(req.body.grant_type || "").trim();
  const clientId = String(req.body.client_id || "").trim();
  const clientSecret = String(req.body.client_secret || "").trim();
  const code = String(req.body.code || "").trim();
  const redirectUri = String(req.body.redirect_uri || "").trim();

  if (!grantType || !clientId || !clientSecret || !code || !redirectUri) {
    return sendTokenError(res, 400, "invalid_request", "grant_type, client_id, client_secret, code and redirect_uri are required");
  }

  if (grantType !== "authorization_code") {
    return sendTokenError(res, 400, "unsupported_grant_type", "Only authorization_code is supported");
  }

  try {
    const client = await db("clients")
      .select(["id", "client_id", "client_secret_hash", "redirect_uris"])
      .where({ client_id: clientId })
      .first();

    if (!client) {
      return sendTokenError(res, 401, "invalid_client", "Client authentication failed");
    }

    const validSecret = await bcrypt.compare(clientSecret, client.client_secret_hash);
    if (!validSecret) {
      return sendTokenError(res, 401, "invalid_client", "Client authentication failed");
    }

    const registeredRedirectUris = parseRedirectUris(client.redirect_uris);
    if (!registeredRedirectUris.includes(redirectUri)) {
      return sendTokenError(res, 400, "invalid_grant", "redirect_uri does not match registered value");
    }

    let authCode;

    await db.transaction(async (trx) => {
      authCode = await trx("auth_codes")
        .where({ code, client_id: client.id })
        .first()
        .forUpdate();

      if (!authCode) {
        throw new Error("invalid_grant:Authorization code not found");
      }

      if (authCode.is_used) {
        throw new Error("invalid_grant:Authorization code already used");
      }

      if (new Date(authCode.expires_at) <= new Date()) {
        throw new Error("invalid_grant:Authorization code expired");
      }

      if (authCode.redirect_uri !== redirectUri) {
        throw new Error("invalid_grant:redirect_uri mismatch for authorization code");
      }

      await trx("auth_codes")
        .where({ id: authCode.id })
        .update({
          is_used: true,
          used_at: trx.fn.now(),
          updated_at: trx.fn.now(),
        });
    });

    const scopeArray = toScopeArray(authCode.scopes);
    const scope = scopeArray.join(" ");
    const accessToken = jwt.sign(
      {
        scope,
        client_id: client.client_id,
      },
      oauthKeys.privateKey,
      {
        algorithm: "RS256",
        keyid: oauthKeys.kid,
        subject: String(authCode.user_id),
        audience: client.client_id,
        issuer: config.oauth.issuer,
        expiresIn: config.oauth.accessTokenExpiresInSeconds,
      }
    );

    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.oauth.accessTokenExpiresInSeconds,
      scope,
    });
  } catch (err) {
    if (String(err.message || "").startsWith("invalid_grant:")) {
      const description = String(err.message).slice("invalid_grant:".length);
      return sendTokenError(res, 400, "invalid_grant", description);
    }

    return sendTokenError(res, 500, "server_error", "Unable to issue token");
  }
});

router.get("/userinfo", async (req, res) => {
  const token = getBearerToken(req);
  if (!token) {
    return sendUserInfoInvalidToken(res, "Missing bearer token");
  }

  try {
    const payload = jwt.verify(token, oauthKeys.publicKey, {
      algorithms: ["RS256"],
      issuer: config.oauth.issuer,
    });

    const user = await db("users")
      .select(["id", "email", "name"])
      .where({ id: payload.sub })
      .first();

    if (!user) {
      return sendUserInfoInvalidToken(res, "Unknown token subject");
    }

    const scopeValues = String(payload.scope || "").split(/\s+/).filter(Boolean);
    const data = {
      sub: user.id,
    };

    if (scopeValues.includes("email")) {
      data.email = user.email;
      data.email_verified = true;
    }

    if (scopeValues.includes("profile")) {
      data.name = user.name;
    }

    return res.json(data);
  } catch (_err) {
    return sendUserInfoInvalidToken(res, "Invalid or expired access token");
  }
});

module.exports = router;
