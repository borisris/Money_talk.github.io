# MoneyTalk V2

A multi-user finance community forum built with Node.js, Express and SQLite.

## Features
- Public Home, Fiat money and Cryptocurrency feeds
- Member registration, login and persistent sessions
- Shared posts stored in a database
- Referral/article links with URL validation
- Likes and comments
- Member profiles
- Admin-only Home news publishing
- Admin dashboard, member role management and moderation
- Responsive layout for desktop and mobile
- Rate limits on authentication and write actions

## Requirements
- Node.js 20 or newer
- npm

## Run locally

```bash
npm install
```

Create a secure session secret and configure your first administrator (recommended):

```bash
# Linux / macOS example
export SESSION_SECRET="replace-with-a-long-random-secret"
export ADMIN_EMAIL="you@example.com"
export ADMIN_PASSWORD="use-a-strong-password-of-at-least-10-characters"
export ADMIN_USERNAME="YourAdminName"
npm start
```

On Windows PowerShell:

```powershell
$env:SESSION_SECRET="replace-with-a-long-random-secret"
$env:ADMIN_EMAIL="you@example.com"
$env:ADMIN_PASSWORD="use-a-strong-password-of-at-least-10-characters"
$env:ADMIN_USERNAME="YourAdminName"
npm start
```

Open http://localhost:3000.

The first administrator account is created at startup if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set and that email does not already exist. Existing account with that email is promoted to administrator. Keep these secrets private.

## Deploy to Railway

1. Create a GitHub repository and upload the contents of this folder (not the ZIP file).
2. In Railway, create a new project and deploy from that GitHub repository.
3. Add a Railway Volume mounted at `/data` so the SQLite database and sessions survive redeployments.
4. Add these Railway Variables:
   - `NODE_ENV` = `production`
   - `DB_DIR` = `/data`
   - `SESSION_SECRET` = a long, unique random secret
   - `ADMIN_EMAIL` = your administrator email
   - `ADMIN_PASSWORD` = a strong password (10+ characters)
   - `ADMIN_USERNAME` = your chosen display name
5. Railway detects Node.js and runs `npm start`. Generate a public domain in Railway's networking settings.

Do not commit `.env`, database files, passwords or session secrets to GitHub.

## Important production notes
- SQLite is appropriate for a modest community. For a larger forum or multiple server replicas, migrate to PostgreSQL and use a shared session store.
- Set a strong unique `SESSION_SECRET` before going live. The development fallback is not suitable for production.
- Configure regular database backups for the Railway volume.
- This starter does not include email verification, password reset, report/appeal workflows, automatic news aggregation or payment processing. Add these before relying on it for a large public community.
- Referral links are user-submitted. Moderate posts and remind members to disclose rewards and independently verify financial services.
