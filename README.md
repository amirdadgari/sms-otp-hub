# SMS OTP Hub

Self-hosted Node.js + SQLite service for receiving SMS OTP webhooks, storing recent messages, and exposing token-protected latest-code APIs for automation.

## Features

- Admin dashboard with tabs for recent messages, apps, and clients.
- Per-client ingest and read tokens.
- Per-app webhook URL and latest-code API URL.
- Sender filtering and configurable OTP extraction regex.
- SQLite persistence with local `data/` storage.
- Docker-ready deployment.

## Requirements

- Node.js 24 or newer
- npm

## Local Setup

```sh
npm install
cp .env.example .env
npm run dev
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
npm run dev
```

Open `http://localhost:8080` and sign in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env`.

## Environment

Copy `.env.example` to `.env` and change the secret values before deploying.

```env
PORT=8080
DATA_DIR=./data
APP_SECRET=change-this-random-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-this-password
TRUST_PROXY=false
```

`APP_SECRET` signs the admin session cookie. Use a long random value in production.

## Scripts

```sh
npm run check
npm start
npm run dev
```

## Docker

```sh
cp .env.example .env
docker compose up -d --build
```

The compose file mounts `./data` into the container so SQLite data survives restarts.

## Android SMS Webhook

Create a client and app in the dashboard, then configure your SMS forwarder:

```text
URL: http://SERVER:8080/api/webhook/{clientSlug}/{appSlug}
Method: POST
Header: Authorization: Bearer {client ingest token}
Header: Content-Type: application/json
Body: {"from":"{from}","body":"{body}"}
```

Accepted sender keys are `from` or `sender`.
Accepted message keys are `body`, `message`, `text`, or `sms`.

## Read Latest Code

```sh
curl -H "Authorization: Bearer {client read token}" \
  http://SERVER:8080/api/latest/{clientSlug}/{appSlug}
```

Response:

```json
{"code":"123456","client":"home","app":"bank","receivedAt":"2026-06-28T19:55:40.000Z"}
```

## GitHub Notes

Do not commit `.env`, `data/`, or `node_modules/`. They are ignored by default.

Before pushing:

```sh
npm run check
git status
```

## License

MIT
