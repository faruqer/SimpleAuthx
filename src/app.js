const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const routes = require("./routes");
const { enforceHttps } = require("./middleware/https");

const app = express();
app.set("trust proxy", 1);

// --------------- Middleware ---------------
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(enforceHttps);

// --------------- Routes ---------------
app.use(routes);

// --------------- 404 handler ---------------
app.use((_req, res) => {
  res.status(404).json({ error: "Not Found" });
});

// --------------- Error handler ---------------
app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

module.exports = app;
