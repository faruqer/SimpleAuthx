const express = require("express");
const healthRouter = require("./health");
const authRouter = require("./auth");
const clientsRouter = require("./clients");

const router = express.Router();

router.use("/health", healthRouter);
router.use("/auth", authRouter);
router.use("/clients", clientsRouter);

module.exports = router;
