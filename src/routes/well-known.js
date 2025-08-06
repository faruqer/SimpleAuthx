const express = require("express");
const { getJwks } = require("../security/oauth-keys");

const router = express.Router();

router.get("/jwks.json", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=300");
  return res.json(getJwks());
});

module.exports = router;
