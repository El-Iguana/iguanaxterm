#!/usr/bin/env python3
VERSION = "1.0.0"

import asyncio
import io
import json
import os
import secrets
import sqlite3
import stat as stat_module
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

import paramiko
import redis.asyncio as aioredis
import uvicorn
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import bcrypt as _bcrypt
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────

_data_dir    = Path(os.getenv("GANXTERM_DATA_DIR", str(Path(__file__).parent)))
DB_PATH      = _data_dir / "ganxterm.db"
STATIC_DIR   = Path(__file__).parent / "static"
REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_TTL  = int(os.getenv("SESSION_TTL_HOURS", "8")) * 3600
COOKIE_NAME  = "ganx_session"
LOGIN_RATE_LIMIT  = int(os.getenv("LOGIN_RATE_LIMIT", "10"))   # max attempts
LOGIN_RATE_WINDOW = int(os.getenv("LOGIN_RATE_WINDOW", "900"))  # seconds (15 min)

_KEY_FILE    = _data_dir / "secret.key"
_CRED_PREFIX = "fernet:"


def _load_or_create_fernet() -> Fernet:
    env_key = os.getenv("GANXTERM_SECRET_KEY", "").strip()
    if env_key:
        return Fernet(env_key.encode())
    if _KEY_FILE.exists():
        return Fernet(_KEY_FILE.read_bytes().strip())
    key = Fernet.generate_key()
    _KEY_FILE.write_bytes(key)
    _KEY_FILE.chmod(0o600)
    return Fernet(key)


_fernet = _load_or_create_fernet()


def _encrypt_cred(value: str) -> str:
    if not value:
        return value
    return _CRED_PREFIX + _fernet.encrypt(value.encode()).decode()


def _decrypt_cred(value: str) -> str:
    if not value or not value.startswith(_CRED_PREFIX):
        return value  # legacy plaintext
    return _fernet.decrypt(value[len(_CRED_PREFIX):].encode()).decode()

_sftp_pool   = ThreadPoolExecutor(max_workers=20, thread_name_prefix="sftp")
redis_client: aioredis.Redis | None = None


def _hash_pw(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(12)).decode()

def _verify_pw(password: str, hashed: str) -> bool:
    return _bcrypt.checkpw(password.encode(), hashed.encode())


# ── Database ──────────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            pw_hash    TEXT    NOT NULL,
            is_admin   INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id),
            name        TEXT    NOT NULL,
            host        TEXT    NOT NULL,
            port        INTEGER DEFAULT 22,
            username    TEXT    NOT NULL,
            password    TEXT    DEFAULT '',
            private_key TEXT    DEFAULT '',
            description TEXT    DEFAULT ''
        )
        """
    )

    # Migrations: add columns that may not exist in older DBs
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    for col, definition in [
        ("user_id",     "INTEGER"),
        ("type",        "TEXT NOT NULL DEFAULT 'ssh'"),
        ("folder",      "TEXT NOT NULL DEFAULT ''"),
    ]:
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {col} {definition}")
    conn.commit()

    # Create default admin if no users exist yet
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        admin_user = os.getenv("GANXTERM_ADMIN_USER", "admin")
        admin_pass = os.getenv("GANXTERM_ADMIN_PASS", "changeme")
        conn.execute(
            "INSERT INTO users (username, pw_hash, is_admin) VALUES (?, ?, 1)",
            (admin_user, _hash_pw(admin_pass)),
        )
        conn.commit()
        print(f"\n{'=' * 55}")
        print(f"  Default admin account created:")
        print(f"    Username : {admin_user}")
        print(f"    Password : {admin_pass}")
        print(f"  !! CHANGE THIS PASSWORD IMMEDIATELY !!")
        print(f"{'=' * 55}\n")

    # Assign orphaned sessions (from migration of old DB) to the first admin
    conn.execute(
        "UPDATE sessions SET user_id = (SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1) "
        "WHERE user_id IS NULL"
    )
    conn.commit()

    # Migrate plaintext credentials to encrypted
    rows = conn.execute("SELECT id, password, private_key FROM sessions").fetchall()
    for row in rows:
        pw = row[1] or ""
        pk = row[2] or ""
        new_pw = _encrypt_cred(pw) if pw and not pw.startswith(_CRED_PREFIX) else pw
        new_pk = _encrypt_cred(pk) if pk and not pk.startswith(_CRED_PREFIX) else pk
        if new_pw != pw or new_pk != pk:
            conn.execute(
                "UPDATE sessions SET password=?, private_key=? WHERE id=?",
                (new_pw, new_pk, row[0]),
            )
    conn.commit()
    conn.close()


def _fetch_session(session_id: int, user_id: int) -> dict:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ? AND user_id = ?",
            (session_id, user_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    s = dict(row)
    s["password"]    = _decrypt_cred(s.get("password") or "")
    s["private_key"] = _decrypt_cred(s.get("private_key") or "")
    return s


# ── SFTP connection manager ───────────────────────────────────────────────────

class _SFTPConn:
    def __init__(self, ssh: paramiko.SSHClient, sftp: paramiko.SFTPClient):
        self.ssh  = ssh
        self.sftp = sftp
        self.lock = threading.Lock()


class SFTPManager:
    def __init__(self):
        self._conns: dict[int, _SFTPConn] = {}
        self._global = threading.Lock()
        self._per_lock: dict[int, threading.Lock] = {}

    def _lock_for(self, sid: int) -> threading.Lock:
        with self._global:
            if sid not in self._per_lock:
                self._per_lock[sid] = threading.Lock()
            return self._per_lock[sid]

    @staticmethod
    def _build(session: dict) -> _SFTPConn:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw: dict = dict(hostname=session["host"], port=session["port"],
                        username=session["username"], timeout=15)
        pk = (session.get("private_key") or "").strip()
        if pk:
            kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(pk))
        else:
            kw["password"] = session["password"]
        ssh.connect(**kw)
        return _SFTPConn(ssh, ssh.open_sftp())

    def get(self, sid: int, session: dict) -> _SFTPConn:
        lock = self._lock_for(sid)
        with lock:
            conn = self._conns.get(sid)
            if conn:
                try:
                    conn.sftp.listdir(".")
                    return conn
                except Exception:
                    try:
                        conn.ssh.close()
                    except Exception:
                        pass
                    del self._conns[sid]
            conn = self._build(session)
            self._conns[sid] = conn
            return conn

    def close(self, sid: int):
        lock = self._lock_for(sid)
        with lock:
            conn = self._conns.pop(sid, None)
            if conn:
                try:
                    conn.ssh.close()
                except Exception:
                    pass

    def close_all(self):
        with self._global:
            ids = list(self._conns.keys())
        for sid in ids:
            self.close(sid)


sftp_manager = SFTPManager()


# ── SFTP helpers ──────────────────────────────────────────────────────────────

def _list_dir(sftp: paramiko.SFTPClient, path: str) -> list[dict]:
    try:
        attrs = sftp.listdir_attr(path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    out = []
    for a in attrs:
        mode   = a.st_mode or 0
        is_dir = stat_module.S_ISDIR(mode)
        is_lnk = stat_module.S_ISLNK(mode)
        out.append({
            "name":        a.filename,
            "type":        "dir" if is_dir else ("link" if is_lnk else "file"),
            "size":        a.st_size or 0,
            "mtime":       int(a.st_mtime or 0),
            "permissions": oct(stat_module.S_IMODE(mode)) if mode else "?",
        })
    out.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
    return out


# ── Telnet IAC helpers ────────────────────────────────────────────────────────

_T_IAC  = 0xFF
_T_SB   = 0xFA
_T_SE   = 0xF0
_T_WILL = 0xFB
_T_WONT = 0xFC
_T_DO   = 0xFD
_T_DONT = 0xFE
_T_ECHO = 0x01
_T_SGA  = 0x03   # Suppress Go Ahead


def _process_iac(data: bytes) -> tuple[bytes, bytes]:
    """Strip Telnet IAC sequences from data; return (display_bytes, response_bytes)."""
    out  = bytearray()
    resp = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b != _T_IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= len(data):
            break
        cmd = data[i + 1]
        if cmd == _T_IAC:                               # escaped 0xFF literal
            out.append(_T_IAC); i += 2
        elif cmd in (_T_WILL, _T_WONT, _T_DO, _T_DONT):
            if i + 2 >= len(data):
                break
            opt = data[i + 2]
            if cmd == _T_WILL:
                resp += bytes([_T_IAC, _T_DO if opt in (_T_ECHO, _T_SGA) else _T_DONT, opt])
            elif cmd == _T_DO:
                resp += bytes([_T_IAC, _T_WILL if opt == _T_SGA else _T_WONT, opt])
            i += 3
        elif cmd == _T_SB:                              # subnegotiation — skip to SE
            j = i + 2
            while j < len(data) - 1:
                if data[j] == _T_IAC and data[j + 1] == _T_SE:
                    j += 2; break
                j += 1
            i = j
        else:
            i += 2
    return bytes(out), bytes(resp)


def _rm_recursive(sftp: paramiko.SFTPClient, path: str):
    try:
        attrs = sftp.listdir_attr(path)
        for a in attrs:
            child = f"{path.rstrip('/')}/{a.filename}"
            if stat_module.S_ISDIR(a.st_mode or 0):
                _rm_recursive(sftp, child)
            else:
                sftp.remove(child)
        sftp.rmdir(path)
    except IOError:
        sftp.remove(path)


# ── App lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    init_db()
    yield
    await redis_client.aclose()
    sftp_manager.close_all()
    _sftp_pool.shutdown(wait=False)


app = FastAPI(title="IguanaXterm", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Pydantic models ───────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    username: str
    password: str

class CreateUserIn(BaseModel):
    username: str
    password: str
    is_admin: bool = False

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

class SessionIn(BaseModel):
    name:        str
    host:        str
    port:        int  = 22
    username:    str  = ""
    password:    str  = ""
    private_key: str  = ""
    description: str  = ""
    type:        str  = "ssh"    # "ssh" | "telnet"
    folder:      str  = ""

class RenameIn(BaseModel):
    old_path: str
    new_path: str

class MkdirIn(BaseModel):
    path: str


# ── Auth dependencies ─────────────────────────────────────────────────────────

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    raw = await redis_client.get(f"session:{token}")
    if not raw:
        raise HTTPException(status_code=401, detail="Session expired")
    await redis_client.expire(f"session:{token}", SESSION_TTL)
    return json.loads(raw)


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Routes: static ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


# ── Routes: auth ──────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(body: LoginIn, request: Request, response: Response):
    ip  = request.client.host if request.client else "unknown"
    key = f"ratelimit:login:{ip}"
    attempts = await redis_client.incr(key)
    if attempts == 1:
        await redis_client.expire(key, LOGIN_RATE_WINDOW)
    if attempts > LOGIN_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many login attempts — try again later")

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (body.username,)
        ).fetchone()
    if not row or not _verify_pw(body.password, row["pw_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token   = secrets.token_urlsafe(32)
    payload = json.dumps({
        "id":       row["id"],
        "username": row["username"],
        "is_admin": bool(row["is_admin"]),
    })
    await redis_client.setex(f"session:{token}", SESSION_TTL, payload)

    response.set_cookie(
        key=COOKIE_NAME, value=token,
        max_age=SESSION_TTL, httponly=True, samesite="lax", path="/",
    )
    return {"username": row["username"], "is_admin": bool(row["is_admin"])}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        await redis_client.delete(f"session:{token}")
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"username": user["username"], "is_admin": user["is_admin"]}


@app.put("/api/auth/password")
async def change_password(body: ChangePasswordIn, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        row = conn.execute("SELECT pw_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not row or not _verify_pw(body.current_password, row["pw_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET pw_hash = ? WHERE id = ?",
            (_hash_pw(body.new_password), user["id"]),
        )
    return {"ok": True}


# ── Routes: admin user management ─────────────────────────────────────────────

@app.get("/api/admin/users")
async def list_users(_: dict = Depends(require_admin)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, is_admin, created_at FROM users ORDER BY username"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/users", status_code=201)
async def create_user(body: CreateUserIn, _: dict = Depends(require_admin)):
    name = body.username.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Username required")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    try:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, pw_hash, is_admin) VALUES (?, ?, ?)",
                (name, _hash_pw(body.password), int(body.is_admin)),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already taken")
    return {"id": uid, "username": name, "is_admin": body.is_admin}


@app.delete("/api/admin/users/{uid}")
async def delete_user(uid: int, user: dict = Depends(require_admin)):
    if uid == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    with get_db() as conn:
        # Close SFTP connections for this user's sessions before deleting
        sids = [r[0] for r in conn.execute(
            "SELECT id FROM sessions WHERE user_id = ?", (uid,)
        ).fetchall()]
        for sid in sids:
            sftp_manager.close(sid)
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        cur = conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


# ── Routes: SSH sessions ──────────────────────────────────────────────────────

@app.get("/api/sessions")
async def list_sessions(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, host, port, username, description, type, folder FROM sessions "
            "WHERE user_id = ? ORDER BY folder, name",
            (user["id"],),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: int, user: dict = Depends(get_current_user)):
    return _fetch_session(session_id, user["id"])


@app.post("/api/sessions", status_code=201)
async def create_session(session: SessionIn, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (user_id, name, host, port, username, password, private_key, description, type, folder) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (user["id"], session.name, session.host, session.port,
             session.username, _encrypt_cred(session.password), _encrypt_cred(session.private_key),
             session.description, session.type, session.folder),
        )
        new_id = cur.lastrowid
    return {"id": new_id, **session.model_dump()}


@app.put("/api/sessions/{session_id}")
async def update_session(session_id: int, session: SessionIn, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE sessions SET name=?, host=?, port=?, username=?, password=?, private_key=?, "
            "description=?, type=?, folder=? WHERE id=? AND user_id=?",
            (session.name, session.host, session.port, session.username,
             _encrypt_cred(session.password), _encrypt_cred(session.private_key),
             session.description, session.type, session.folder, session_id, user["id"]),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    sftp_manager.close(session_id)
    return {"id": session_id, **session.model_dump()}


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: int, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM sessions WHERE id = ? AND user_id = ?",
            (session_id, user["id"]),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    sftp_manager.close(session_id)
    return {"ok": True}


# ── Routes: SFTP ──────────────────────────────────────────────────────────────

@app.get("/api/sftp/{session_id}/ls")
async def sftp_ls(session_id: int, path: str = "/", user: dict = Depends(get_current_user)):
    session = _fetch_session(session_id, user["id"])
    loop    = asyncio.get_event_loop()

    def _run():
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            resolved = conn.sftp.normalize(path) if path in ("~", ".") else path
            return _list_dir(conn.sftp, resolved), resolved

    entries, resolved = await loop.run_in_executor(_sftp_pool, _run)
    return {"path": resolved, "entries": entries}


@app.post("/api/sftp/{session_id}/mkdir")
async def sftp_mkdir(session_id: int, body: MkdirIn, user: dict = Depends(get_current_user)):
    session = _fetch_session(session_id, user["id"])
    loop    = asyncio.get_event_loop()

    def _run():
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            try:
                conn.sftp.mkdir(body.path)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    await loop.run_in_executor(_sftp_pool, _run)
    return {"ok": True}


@app.post("/api/sftp/{session_id}/rename")
async def sftp_rename(session_id: int, body: RenameIn, user: dict = Depends(get_current_user)):
    session = _fetch_session(session_id, user["id"])
    loop    = asyncio.get_event_loop()

    def _run():
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            try:
                conn.sftp.rename(body.old_path, body.new_path)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    await loop.run_in_executor(_sftp_pool, _run)
    return {"ok": True}


@app.delete("/api/sftp/{session_id}/delete")
async def sftp_delete(session_id: int, path: str, user: dict = Depends(get_current_user)):
    session = _fetch_session(session_id, user["id"])
    loop    = asyncio.get_event_loop()

    def _run():
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            try:
                _rm_recursive(conn.sftp, path)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    await loop.run_in_executor(_sftp_pool, _run)
    return {"ok": True}


@app.post("/api/sftp/{session_id}/upload")
async def sftp_upload(
    session_id: int,
    path:       str        = Form(...),
    file:       UploadFile = File(...),
    user:       dict       = Depends(get_current_user),
):
    session = _fetch_session(session_id, user["id"])
    content = await file.read()
    remote_path = f"{path.rstrip('/')}/{file.filename}"
    loop = asyncio.get_event_loop()

    def _run():
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            try:
                conn.sftp.putfo(io.BytesIO(content), remote_path)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    await loop.run_in_executor(_sftp_pool, _run)
    return {"ok": True, "path": remote_path}


@app.get("/api/sftp/{session_id}/download")
async def sftp_download(session_id: int, path: str, user: dict = Depends(get_current_user)):
    session = _fetch_session(session_id, user["id"])
    loop    = asyncio.get_event_loop()

    def _run() -> bytes:
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            buf = io.BytesIO()
            try:
                conn.sftp.getfo(path, buf)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            return buf.getvalue()

    content  = await loop.run_in_executor(_sftp_pool, _run)
    filename = path.split("/")[-1]
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── WebSocket: SSH terminal ───────────────────────────────────────────────────

async def _ws_send(ws: WebSocket, msg_type: str, data: str):
    await ws.send_text(json.dumps({"type": msg_type, "data": data}))


@app.websocket("/ws/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: int):
    # Auth check — cookies are sent automatically by the browser for same-origin WS
    token = websocket.cookies.get(COOKIE_NAME)
    user  = None
    if token:
        raw = await redis_client.get(f"session:{token}")
        if raw:
            await redis_client.expire(f"session:{token}", SESSION_TTL)
            user = json.loads(raw)

    await websocket.accept()

    if not user:
        await _ws_send(websocket, "error", "Not authenticated")
        await websocket.close(code=4401)
        return

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ? AND user_id = ?",
            (session_id, user["id"]),
        ).fetchone()

    if not row:
        await _ws_send(websocket, "error", "Session not found")
        await websocket.close()
        return

    session = dict(row)
    session["password"]    = _decrypt_cred(session.get("password") or "")
    session["private_key"] = _decrypt_cred(session.get("private_key") or "")

    # ── Telnet branch ─────────────────────────────────────────────────────────
    if session.get("type", "ssh") == "telnet":
        try:
            reader, writer = await asyncio.open_connection(session["host"], session["port"])
        except Exception as exc:
            await _ws_send(websocket, "error", str(exc))
            await websocket.close()
            return

        # Negotiate: WILL SGA, DO SGA, DO ECHO
        writer.write(bytes([_T_IAC, _T_WILL, _T_SGA,
                            _T_IAC, _T_DO,   _T_SGA,
                            _T_IAC, _T_DO,   _T_ECHO]))
        await writer.drain()
        await _ws_send(websocket, "connected", session["host"])

        async def pump_telnet():
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                except asyncio.TimeoutError:
                    continue
                if not data:
                    await _ws_send(websocket, "disconnected", "Connection closed")
                    break
                display, response = _process_iac(data)
                if response:
                    writer.write(response)
                    await writer.drain()
                if display:
                    await _ws_send(websocket, "output", display.decode("utf-8", errors="replace"))

        pump = asyncio.create_task(pump_telnet())
        try:
            while True:
                raw = await websocket.receive_text()
                msg = json.loads(raw)
                if msg["type"] == "input":
                    writer.write(msg["data"].encode())
                    await writer.drain()
                elif msg["type"] == "resize":
                    pass  # Telnet has no PTY resize
        except WebSocketDisconnect:
            pass
        finally:
            pump.cancel()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return

    # ── SSH branch ────────────────────────────────────────────────────────────
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        kw: dict = dict(
            hostname=session["host"],
            port=session["port"],
            username=session["username"],
            timeout=15,
        )
        pk = (session.get("private_key") or "").strip()
        if pk:
            kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(pk))
        else:
            kw["password"] = session["password"]

        ssh.connect(**kw)
        transport = ssh.get_transport()
        if transport:
            transport.set_keepalive(30)   # SSH keepalive every 30 s
        channel = ssh.invoke_shell(term="xterm-256color", width=220, height=50)
        channel.setblocking(False)

        await _ws_send(websocket, "connected", session["host"])

        async def pump_ssh():
            loop = asyncio.get_event_loop()
            while True:
                await asyncio.sleep(0.02)
                try:
                    ready = await loop.run_in_executor(None, channel.recv_ready)
                    if ready:
                        data = channel.recv(32768)
                        if data:
                            await _ws_send(
                                websocket, "output",
                                data.decode("utf-8", errors="replace"),
                            )
                    if channel.exit_status_ready():
                        await _ws_send(websocket, "disconnected", "Remote session ended")
                        break
                except Exception:
                    break

        pump = asyncio.create_task(pump_ssh())
        try:
            while True:
                raw = await websocket.receive_text()
                msg = json.loads(raw)
                if msg["type"] == "input":
                    channel.sendall(msg["data"].encode())
                elif msg["type"] == "resize":
                    channel.resize_pty(width=int(msg["cols"]), height=int(msg["rows"]))
        except WebSocketDisconnect:
            pass
        finally:
            pump.cancel()
            try:
                channel.close()
            except Exception:
                pass
            ssh.close()

    except Exception as exc:
        try:
            await _ws_send(websocket, "error", str(exc))
            await websocket.close()
        except Exception:
            pass
        ssh.close()


if __name__ == "__main__":
    print(f"""
  ___                               __  __
 |_ _|__ _ _  _  __ _ _ _  __ _   \\ \\/ /_ ______ _ __
  | |/ _` | || |/ _` | ' \\/ _` |   >  <  / -_) '_| '  \\
 |___\\__, |\\_,_|\\__,_|_||_\\__,_|  /_/\\_\\\\___|_| |_|_|_|
        |_|
  Browser-based SSH/Telnet Terminal Manager
  Version   : {VERSION}
  Developer : OldManGan <eliguana@protonmail.com>
  Port      : 8765
    """, flush=True)
    uvicorn.run("main:app", host="0.0.0.0", port=8765, reload=False)
