const express = require("express");
const db = require("../db");

const router = express.Router();

/**
 * GET /health
 * Returns server and database health status.
 */
router.get("/", async (_req, res) => {
  try {
    await db.raw("SELECT 1");
    return res.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      database: "connected",
    });
  } catch (err) {
    return res.status(503).json({
      status: "error",
      timestamp: new Date().toISOString(),
      database: "disconnected",
      message: err.message,
    });
  }
});

module.exports = router;
