# IguanaXterm — Claude Context

## What this project is
IguanaXterm is a browser-based SSH/Telnet terminal manager with SFTP support.
Brand name: **IguanaXterm**. Internal/file names remain `ganxterm` (do not rename files or env vars).
Mascot: `el_iguana.png` — a dapper iguana in a fez with a cigar.

## Architecture
- **Single Python backend** — `main.py` (FastAPI, ~820 lines)
- **Single HTML frontend** — `static/index.html` (xterm.js SPA, ~1000 lines)
- **No build step** — vanilla JS, CSS in `<style>`, CDN scripts only
- **Database** — SQLite via stdlib `sqlite3`, `@contextmanager get_db()` (auto-commit/rollback/close)
- **Sessions** — Redis (`redis.asyncio`) with sliding TTL, HttpOnly cookie

## Stack
| Layer | Tech |
|---|---|
| Backend | FastAPI + Uvicorn |
| SSH/SFTP | Paramiko |
| Telnet | `asyncio.open_connection` + IAC parser |
| Auth | bcrypt (direct, not passlib) + Redis sessions |
| Frontend terminal | xterm.js 5.3.0, xterm-addon-fit 0.8.0, xterm-addon-search 0.13.0 |
| Deployment | Podman + podman-compose (`compose.yaml`) |

## Config (env vars)
| Var | Default | Purpose |
|---|---|---|
| `GANXTERM_DATA_DIR` | script dir | SQLite DB location |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `SESSION_TTL_HOURS` | `8` | Sliding session TTL |
| `GANXTERM_ADMIN_USER` | `admin` | First-run admin username |
| `GANXTERM_ADMIN_PASS` | `changeme` | First-run admin password |

## Database schema
```
users    (id, username, pw_hash, is_admin, created_at)
sessions (id, user_id FK, name, host, port, username, password,
          private_key, description, type, folder)
```
- `type`: `'ssh'` | `'telnet'` (default `'ssh'`)
- `folder`: empty string = ungrouped; named string = collapsible sidebar group
- SSH passwords stored in plaintext — keep DB file permissions tight
- New columns added via migration in `init_db()` — safe to run against existing DB

## Auth flow
- Login → `POST /api/auth/login` → sets `ganx_session` HttpOnly cookie
- All HTTP routes: `get_current_user` dependency reads cookie → Redis
- WebSocket auth: manual cookie check at top of `terminal_ws` (browser sends same-origin cookies automatically)
- Admin routes: `require_admin` dependency wraps `get_current_user`

## Key patterns
- **Password hashing**: `_hash_pw()` / `_verify_pw()` using `bcrypt` directly — **do not use passlib** (incompatible with bcrypt 4.x)
- **SFTP**: `SFTPManager` class, pooled connections keyed by session DB id, thread-safe via per-session locks, runs in `ThreadPoolExecutor`
- **Terminal WebSocket**: `terminal_ws` — telnet branch exits early with `return`; SSH branch follows
- **SSH keepalive**: `transport.set_keepalive(30)` after `ssh.connect()`
- **Telnet IAC**: `_process_iac(data)` strips sequences, returns `(display_bytes, response_bytes)`
- **Frontend reconnect**: exponential backoff in `ws.onclose` (1s→2s→4s…30s cap, 5 attempts); `inputDisposable` disposed before re-registering `onData` to prevent duplicates
- **Sidebar folders**: `folderState` map + `renderSidebar()` groups sessions; `sessionCardHTML()` renders individual cards

## Deployment
```bash
# Build and start
podman compose build --no-cache && podman compose up -d

# Logs
podman compose logs -f

# Stop
podman compose down
```
Two named volumes: `ganxterm_data` (SQLite at `/data`), `redis_data`.
App runs on port **8765**.

## File layout
```
main.py              # Entire backend
static/
  index.html         # Entire frontend SPA
  el_iguana.png      # Mascot image
Containerfile        # python:3.12-slim, installs deps, copies app
compose.yaml         # ganxterm + redis services
requirements.txt     # fastapi, uvicorn, paramiko, websockets,
                     # python-multipart, redis, bcrypt
.env.example         # Template for env overrides
.gitignore
.containerignore
```
