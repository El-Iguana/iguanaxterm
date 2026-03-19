# IguanaXterm

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

A browser-based SSH/Telnet terminal manager with SFTP support. Manage all your remote connections from a single web UI — no client software required.

![IguanaXterm](static/el_iguana.png)

## Features

- **SSH & Telnet** — connect to any host via SSH or Telnet directly in the browser
- **SFTP** — browse, upload, and download files over SSH
- **Multi-tab** — open multiple terminal sessions simultaneously
- **Session library** — save connections with credentials, organized into folders
- **Terminal search** — Ctrl+F to search scrollback
- **Auto-reconnect** — exponential backoff reconnect on disconnect (up to 5 attempts)
- **SSH keepalive** — 30-second keepalive prevents idle disconnects
- **Multi-user** — each user has their own session library; admin panel for user management
- **Persistent login** — Redis-backed sessions with sliding TTL; refresh the page without re-logging in
- **Encrypted credentials** — SSH passwords and private keys encrypted at rest with Fernet (AES-128)
- **Login rate limiting** — brute-force protection on the login endpoint (10 attempts / 15 min per IP)

## Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI + Uvicorn |
| SSH/SFTP | Paramiko |
| Telnet | asyncio + IAC parser |
| Auth | bcrypt + Redis sessions |
| Frontend | xterm.js 5.3.0, vanilla JS/CSS |
| Deployment | Podman or Docker |

## Quick Start

```bash
git clone https://github.com/El-Iguana/iguanaxterm.git
cd iguanaxterm

# Optional: copy and edit environment overrides
cp .env.example .env
```

### Podman

**Prerequisites:** `podman` and `podman-compose`

```bash
podman compose build --no-cache && podman compose up -d
podman compose logs -f
```

### Docker

**Prerequisites:** `docker` and `docker compose`

```bash
docker compose -f docker-compose.yaml build --no-cache && docker compose -f docker-compose.yaml up -d
docker compose -f docker-compose.yaml logs -f
```

Open [http://localhost:8765](http://localhost:8765) and log in with `admin` / `changeme` (change this immediately).

## Configuration

Copy `.env.example` to `.env` and set any overrides:

| Variable | Default | Description |
|---|---|---|
| `GANXTERM_ADMIN_USER` | `admin` | Initial admin username (first run only) |
| `GANXTERM_ADMIN_PASS` | `changeme` | Initial admin password (first run only) |
| `SESSION_TTL_HOURS` | `8` | Sliding session timeout in hours |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `GANXTERM_DATA_DIR` | script dir | Directory for the SQLite database |
| `GANXTERM_SECRET_KEY` | *(auto-generated)* | Fernet key for credential encryption; auto-generated and saved to `secret.key` on first run if not set |
| `LOGIN_RATE_LIMIT` | `10` | Max login attempts per IP per window |
| `LOGIN_RATE_WINDOW` | `900` | Rate limit window in seconds (default 15 min) |

## Running Locally (without containers)

```bash
pip install -r requirements.txt
# Requires a running Redis instance
REDIS_URL=redis://localhost:6379/0 python main.py
```

## Data Persistence

When running via Podman or Docker, two named volumes are used:

- `ganxterm_data` — SQLite database and encryption key, mounted at `/data`
- `redis_data` — Redis persistence

Keep the `ganxterm_data` volume and any `.env` file with tight permissions. If you set `GANXTERM_SECRET_KEY` via env var instead of relying on the auto-generated `secret.key` file, back it up — losing it means stored credentials cannot be decrypted.

## Security Notes

- Change the default admin password immediately after first login
- Run behind a reverse proxy with TLS (nginx, Caddy, etc.) — the app itself does not terminate SSL
- The `ganx_session` cookie is HttpOnly and `SameSite=lax`
- Credentials are encrypted at rest; the encryption key lives in `secret.key` inside the `ganxterm_data` volume
