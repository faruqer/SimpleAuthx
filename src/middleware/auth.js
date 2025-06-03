const jwt = require("jsonwebtoken");
const config = require("../config");

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || "";
  return cookieHeader.split(";").reduce((acc, part) => {
    const [key, ...rest] = part.trim().split("=");
    if (!key) {
      return acc;
    }
    acc[key] = decodeURIComponent(rest.join("="));
    return acc;
  }, {});
}

function getTokenFromRequest(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }

  const cookies = parseCookies(req);
  if (cookies.simpleauthx_token) {
    return cookies.simpleauthx_token;
  }

  return null;
}

function requireAuth(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const payload = jwt.verify(token, config.jwt.secret);
    req.user = {
      id: payload.sub,
      email: payload.email,
    };
    return next();
  } catch (_err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = {
  requireAuth,
  getTokenFromRequest,
};
