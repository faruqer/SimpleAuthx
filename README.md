# SimpleAuthx

SimpleAuthx is an OAuth2-based Identity Provider (IdP) implementing the Authorization Code flow with consent, token exchange, and user info retrieval.

## Features Implemented

- User registration/login with hashed passwords (`bcryptjs`)
- Company client registration with hashed `client_secret`
- OAuth authorization endpoint with consent screen
- Authorization code issuance (5 min expiry, single-use)
- Token exchange endpoint (`/oauth/token`)
- RS256 access token signing with JWKS publishing
- UserInfo endpoint (`/oauth/userinfo`) with scope-based claims
- Security hardening:
  - HTTPS enforcement (production by default)
  - OAuth endpoint rate limiting
  - Strict redirect URI matching
  - CSRF protection on consent via state + CSRF token
  - OAuth-style error responses

## Tech Stack

- Node.js + Express
- PostgreSQL
- Knex migrations
- JSON Web Tokens (`jsonwebtoken`)

## Setup

1. Install dependencies

```bash
npm install
```

2. Configure environment

Copy `.env.example` to `.env` and set:

- Database credentials
- `JWT_SECRET`
- `OAUTH_ISSUER`
- Optional: `OAUTH_PRIVATE_KEY` / `OAUTH_PUBLIC_KEY` (if omitted, dev keys are auto-generated at runtime)

3. Run migrations

```bash
npm run migrate
```

4. Start server

```bash
npm run dev
```

## Endpoints

### Health

- `GET /health`

### User Authentication

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`

### Client Management

- `POST /clients/register`
- `GET /clients/:id`

### OAuth

- `GET /oauth/authorize`
- `GET /oauth/consent`
- `POST /oauth/consent`
- `POST /oauth/token`
- `GET /oauth/userinfo`
- `GET /.well-known/jwks.json`

## OAuth Authorization Code Flow

1. Client sends user to:

`GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=email%20profile&state=...`

2. User logs in (if needed), sees consent screen, then approves.

3. SimpleAuthx redirects back to client:

`https://client.com/callback?code=AUTH_CODE&state=STATE`

4. Client exchanges code:

`POST /oauth/token`

Body:

```json
{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE",
  "redirect_uri": "https://client.com/callback",
  "client_id": "...",
  "client_secret": "..."
}
```

5. Client uses returned access token:

`GET /oauth/userinfo` with `Authorization: Bearer <access_token>`

## Scope Behavior

- `email` scope: returns `email`, `email_verified`
- `profile` scope: returns `name`
- always returns `sub`

## Security Notes

- Access tokens are RS256-signed and verifiable via JWKS.
- Authorization codes are single-use and expire in 5 minutes by default.
- Redirect URI is strictly matched against registered values.
- Consent POST includes CSRF validation.
- OAuth responses include standard error structures where applicable.

## Current Known Issue

If migrations fail with:

`password authentication failed for user "postgres"`

update PostgreSQL credentials in `.env` (`DB_USER`, `DB_PASSWORD`, etc.) and rerun:

```bash
npm run migrate
```
