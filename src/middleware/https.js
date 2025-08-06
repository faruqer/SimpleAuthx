const config = require("../config");

function enforceHttps(req, res, next) {
  if (!config.security.enforceHttps) {
    return next();
  }

  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").toLowerCase();
  const isSecure = req.secure || forwardedProto === "https";

  if (isSecure) {
    return next();
  }

  if (req.path.startsWith("/oauth") || req.path.startsWith("/.well-known")) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "HTTPS is required for OAuth endpoints",
    });
  }

  return res.status(426).json({ error: "HTTPS required" });
}

module.exports = {
  enforceHttps,
};
