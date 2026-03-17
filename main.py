import asyncio
import io
import json
import sqlite3
import stat as stat_module
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

import paramiko
import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DB_PATH = Path(__file__).parent / "ganxterm.db"
STATIC_DIR = Path(__file__).parent / "static"
_sftp_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix="sftp")


# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            host        TEXT NOT NULL,
            port        INTEGER DEFAULT 22,
            username    TEXT NOT NULL,
            password    TEXT DEFAULT '',
            private_key TEXT DEFAULT '',
            description TEXT DEFAULT ''
        )
        """
    )
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _fetch_session(session_id: int) -> dict:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return dict(row)


# ── SFTP connection manager ───────────────────────────────────────────────────

class _SFTPConn:
    """Wraps a persistent SSH+SFTP connection with a per-session lock."""
    def __init__(self, ssh: paramiko.SSHClient, sftp: paramiko.SFTPClient):
        self.ssh = ssh
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
        return _SFTPConn(ssh, ssh.open_sftp())

    def get(self, sid: int, session: dict) -> _SFTPConn:
        lock = self._lock_for(sid)
        with lock:
            conn = self._conns.get(sid)
            if conn:
                try:
                    conn.sftp.listdir(".")      # health-check
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
        mode = a.st_mode or 0
        is_dir = stat_module.S_ISDIR(mode)
        is_link = stat_module.S_ISLNK(mode)
        out.append(
            {
                "name": a.filename,
                "type": "dir" if is_dir else ("link" if is_link else "file"),
                "size": a.st_size or 0,
                "mtime": int(a.st_mtime or 0),
                "permissions": oct(stat_module.S_IMODE(mode)) if mode else "?",
            }
        )
    out.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
    return out


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
    init_db()
    yield
    sftp_manager.close_all()
    _sftp_pool.shutdown(wait=False)


app = FastAPI(title="GanXterm", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Pydantic models ───────────────────────────────────────────────────────────

class SessionIn(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    password: str = ""
    private_key: str = ""
    description: str = ""


class RenameIn(BaseModel):
    old_path: str
    new_path: str


class MkdirIn(BaseModel):
    path: str


# ── Routes: static ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


# ── Routes: sessions ──────────────────────────────────────────────────────────

@app.get("/api/sessions")
async def list_sessions():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, host, port, username, description FROM sessions ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: int):
    return _fetch_session(session_id)


@app.post("/api/sessions", status_code=201)
async def create_session(session: SessionIn):
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (name, host, port, username, password, private_key, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session.name, session.host, session.port, session.username,
                session.password, session.private_key, session.description,
            ),
        )
        conn.commit()
        new_id = cur.lastrowid
    return {"id": new_id, **session.model_dump()}


@app.put("/api/sessions/{session_id}")
async def update_session(session_id: int, session: SessionIn):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE sessions SET name=?, host=?, port=?, username=?, password=?, private_key=?, description=? "
            "WHERE id=?",
            (
                session.name, session.host, session.port, session.username,
                session.password, session.private_key, session.description,
                session_id,
            ),
        )
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    sftp_manager.close(session_id)   # force reconnect if credentials changed
    return {"id": session_id, **session.model_dump()}


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: int):
    with get_db() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    sftp_manager.close(session_id)
    return {"ok": True}


# ── Routes: SFTP ──────────────────────────────────────────────────────────────

@app.get("/api/sftp/{session_id}/ls")
async def sftp_ls(session_id: int, path: str = "/"):
    session = _fetch_session(session_id)
    loop = asyncio.get_event_loop()

    def _run():
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            # Resolve home on first call
            resolved = conn.sftp.normalize(path) if path in ("~", ".") else path
            return _list_dir(conn.sftp, resolved), resolved

    entries, resolved = await loop.run_in_executor(_sftp_pool, _run)
    return {"path": resolved, "entries": entries}


@app.post("/api/sftp/{session_id}/mkdir")
async def sftp_mkdir(session_id: int, body: MkdirIn):
    session = _fetch_session(session_id)
    loop = asyncio.get_event_loop()

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
async def sftp_rename(session_id: int, body: RenameIn):
    session = _fetch_session(session_id)
    loop = asyncio.get_event_loop()

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
async def sftp_delete(session_id: int, path: str):
    session = _fetch_session(session_id)
    loop = asyncio.get_event_loop()

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
    path: str = Form(...),
    file: UploadFile = File(...),
):
    session = _fetch_session(session_id)
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
async def sftp_download(session_id: int, path: str):
    session = _fetch_session(session_id)
    loop = asyncio.get_event_loop()

    def _run() -> bytes:
        conn = sftp_manager.get(session_id, session)
        with conn.lock:
            buf = io.BytesIO()
            try:
                conn.sftp.getfo(path, buf)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            return buf.getvalue()

    content = await loop.run_in_executor(_sftp_pool, _run)
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
    await websocket.accept()

    with get_db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        await _ws_send(websocket, "error", "Session not found")
        await websocket.close()
        return

    session = dict(row)
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
    uvicorn.run("main:app", host="0.0.0.0", port=8765, reload=True)
