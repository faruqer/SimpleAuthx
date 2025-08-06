function createRateLimiter({ windowMs, maxRequests, keyPrefix = "global" }) {
  const bucket = new Map();

  function cleanup(now) {
    for (const [key, item] of bucket.entries()) {
      if (item.resetAt <= now) {
        bucket.delete(key);
      }
    }
  }

  return function rateLimit(req, res, next) {
    const now = Date.now();
    cleanup(now);

    const clientKey = `${keyPrefix}:${req.ip || "unknown"}`;
    const current = bucket.get(clientKey);

    if (!current || current.resetAt <= now) {
      bucket.set(clientKey, {
        count: 1,
        resetAt: now + windowMs,
      });
      return next();
    }

    if (current.count >= maxRequests) {
      const retryAfterSeconds = Math.ceil((current.resetAt - now) / 1000);
      res.setHeader("Retry-After", String(retryAfterSeconds));
      return res.status(429).json({
        error: "temporarily_unavailable",
        error_description: "Rate limit exceeded. Try again later.",
      });
    }

    current.count += 1;
    bucket.set(clientKey, current);
    return next();
  };
}

module.exports = {
  createRateLimiter,
};
