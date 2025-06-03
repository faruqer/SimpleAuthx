const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../db");
const config = require("../config");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();
const SALT_ROUNDS = 12;

function createToken(user) {
  return jwt.sign(
    {
      email: user.email,
    },
    config.jwt.secret,
    {
      subject: String(user.id),
      expiresIn: config.jwt.expiresIn,
    }
  );
}

function setAuthCookie(res, token) {
  res.cookie("simpleauthx_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: config.env === "production",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function resolveSafeNext(nextValue) {
  const next = String(nextValue || "").trim();
  if (!next) {
    return null;
  }
  if (!next.startsWith("/") || next.startsWith("//")) {
    return null;
  }
  return next;
}

router.get("/login", (req, res) => {
  const next = resolveSafeNext(req.query.next);
  return res.status(401).json({
    message: "Login required",
    login_endpoint: "/auth/login",
    next,
  });
});

router.post("/register", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const name = req.body.name ? String(req.body.name).trim() : null;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const existingUser = await db("users").where({ email }).first();
    if (existingUser) {
      return res.status(409).json({ error: "Email is already registered" });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const [createdUser] = await db("users")
      .insert({
        email,
        password_hash: passwordHash,
        name,
      })
      .returning(["id", "email", "name", "created_at"]);

    const token = createToken(createdUser);
    setAuthCookie(res, token);

    return res.status(201).json({
      user: createdUser,
      token,
      token_type: "Bearer",
      expires_in: config.jwt.expiresIn,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await db("users").where({ email }).first();
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = createToken(user);
    setAuthCookie(res, token);

    const next = resolveSafeNext(req.query.next || req.body.next);
    if (next) {
      return res.redirect(302, next);
    }

    return res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      token,
      token_type: "Bearer",
      expires_in: config.jwt.expiresIn,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await db("users")
      .select(["id", "email", "name", "created_at", "updated_at"])
      .where({ id: req.user.id })
      .first();

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.json({ user });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
