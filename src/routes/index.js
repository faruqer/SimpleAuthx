const express = require("express");
const healthRouter = require("./health");
const authRouter = require("./auth");
const clientsRouter = require("./clients");
const oauthRouter = require("./oauth");
const wellKnownRouter = require("./well-known");
const config = require("../config");
const { createRateLimiter } = require("../middleware/rate-limit");

const router = express.Router();
const oauthRateLimit = createRateLimiter({
	windowMs: config.rateLimit.windowMs,
	maxRequests: config.rateLimit.oauthMaxRequests,
	keyPrefix: "oauth",
});

router.use("/health", healthRouter);
router.use("/auth", authRouter);
router.use("/clients", clientsRouter);
router.use("/.well-known", wellKnownRouter);
router.use("/oauth", oauthRateLimit, oauthRouter);

module.exports = router;
