require("dotenv").config();

const env = process.env.NODE_ENV || "development";

const config = {
  env,
  port: parseInt(process.env.PORT, 10) || 3000,
  db: {
    host: process.env.DB_HOST || "localhost",
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    name: process.env.DB_NAME || "simpleauthx",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "postgres",
  },
  jwt: {
    secret: process.env.JWT_SECRET || "dev_jwt_secret_change_me",
    expiresIn: process.env.JWT_EXPIRES_IN || "7d",
  },
  oauth: {
    issuer: process.env.OAUTH_ISSUER || `http://localhost:${parseInt(process.env.PORT, 10) || 3000}`,
    accessTokenExpiresInSeconds: parseInt(process.env.OAUTH_ACCESS_TOKEN_EXPIRES_IN_SECONDS, 10) || 3600,
    authCodeExpiresInSeconds: parseInt(process.env.OAUTH_AUTH_CODE_EXPIRES_IN_SECONDS, 10) || 300,
  },
  security: {
    enforceHttps: process.env.ENFORCE_HTTPS === "true" || env === "production",
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000,
    oauthMaxRequests: parseInt(process.env.RATE_LIMIT_OAUTH_MAX_REQUESTS, 10) || 60,
  },
};

module.exports = config;
