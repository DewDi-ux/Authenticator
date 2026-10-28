"""
app.store — слой хранения: SQLite (учебный стенд) с чистым интерфейсом репозитория.

В промышленной версии заменяется на PostgreSQL + SQLAlchemy без изменения API.
Все секреты (seed TOTP, хэши резервных кодов) хранятся в защищённом виде.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import security

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "mfa.db"
_lock = threading.Lock()

AUTHED_TTL = 8 * 3600.0   # время жизни авторизованной сессии (совпадает с cookie)


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id TEXT PRIMARY KEY,
                login TEXT UNIQUE NOT NULL,
                full_name TEXT,
                pass_hash TEXT NOT NULL,
                totp_enc TEXT,                 -- AES-GCM(seed)
                recovery_hashes TEXT,          -- JSON list sha256(recovery_code)
                mfa_enabled INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0,   -- lockout до timestamp
                created_at REAL
            );
            CREATE TABLE IF NOT EXISTS sessions(
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                stage TEXT NOT NULL,           -- password | mfa | step_up | setup | authed
                ip TEXT, user_agent TEXT,
                last_ua TEXT,                  -- «доверительный» UA прошлых входов
                created_at REAL, expires_at REAL,
                risk_score INTEGER DEFAULT 0   -- оценка риска при создании сессии
            );
            CREATE TABLE IF NOT EXISTS audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, event TEXT, actor TEXT, ip TEXT,
                success INTEGER, details TEXT
            );
            CREATE TABLE IF NOT EXISTS password_resets(
                token_hash TEXT PRIMARY KEY,   -- sha256(токен из письма), plaintext не храним
                user_id TEXT NOT NULL,
                created_at REAL, expires_at REAL,
                used_at REAL                   -- NULL = токен ещё не погашен
            );
            """
        )
        # мягкая миграция стендов с ранней схемой: добавить недостающие столбцы
        cols = {r["name"] for r in c.execute("PRAGMA table_info(sessions)")}
        for col, decl in (("last_ua", "TEXT"), ("risk_score", "INTEGER DEFAULT 0")):
            if col not in cols:
                c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {decl}")
        ucols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "email" not in ucols:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")


# ---------------------------------------------------------------------------
@dataclass
class User:
    id: str
    login: str
    full_name: str
    pass_hash: str
    totp_enc: str | None
    recovery_hashes: list[str]
    mfa_enabled: bool
    failed_attempts: int
    locked_until: float
    email: str = ""

    @staticmethod
    def from_row(r: sqlite3.Row) -> "User":
        return User(
            id=r["id"], login=r["login"], full_name=r["full_name"] or "",
            pass_hash=r["pass_hash"], totp_enc=r["totp_enc"],
            recovery_hashes=json.loads(r["recovery_hashes"] or "[]"),
            mfa_enabled=bool(r["mfa_enabled"]),
            failed_attempts=r["failed_attempts"], locked_until=r["locked_until"],
            email=(r["email"] if "email" in r.keys() else "") or "",
        )


def create_user(login: str, password: str, full_name: str = "",
                email: str = "") -> User:
    errors = security.check_password_policy(password, login)
    if errors:
        raise ValueError("; ".join(errors))
    uid = uuid.uuid4().hex
    now = time.time()
    with _lock, _conn() as c:
        cur = c.execute("SELECT 1 FROM users WHERE login=?", (login,))
        if cur.fetchone():
            raise ValueError("Логин уже занят.")
        c.execute(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, login, full_name, security.hash_password(password),
             None, None, 0, 0, 0.0, now, email.strip().lower()),
        )
    audit("user.created", actor=login)
    return get_user_by_login(login)  # type: ignore[return-value]


def get_user_by_login(login: str) -> User | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
    return User.from_row(r) if r else None


def get_user_by_email(email: str) -> User | None:
    """Поиск учётной записи по почте (для восстановления пароля)."""
    email = (email or "").strip().lower()
    if not email:
        return None
    with _conn() as c:
        r = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return User.from_row(r) if r else None


def get_user_by_id(user_id: str) -> User | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return User.from_row(r) if r else None


def update_user(u: User) -> None:
    with _lock, _conn() as c:
        c.execute(
            "UPDATE users SET pass_hash=?, totp_enc=?, recovery_hashes=?,"
            " mfa_enabled=?, failed_attempts=?, locked_until=?, email=? WHERE id=?",
            (u.pass_hash, u.totp_enc, json.dumps(u.recovery_hashes),
             int(u.mfa_enabled), u.failed_attempts, u.locked_until,
             (u.email or "").strip().lower(), u.id),
        )


# ---------------------------------------------------------------------------
# Токены восстановления пароля (одноразовые; в БД — только sha256 токена)
# ---------------------------------------------------------------------------
RESET_TTL_SEC = 15 * 60     # ссылка в письме живёт 15 минут


def create_reset_token(user_id: str) -> str:
    """Создаёт одноразовый токен сброса; возвращает PLAINTEXT токена
    (только для ссылки в письме). В базе — хэш: утечка SQLite/дампа не
    даёт готовых активных ссылок на смену пароля."""
    import hashlib
    import secrets as _secrets
    token = _secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    with _lock, _conn() as c:
        c.execute("DELETE FROM password_resets WHERE expires_at < ?", (now,))
        c.execute(
            "INSERT INTO password_resets(token_hash, user_id, created_at,"
            " expires_at, used_at) VALUES (?,?,?,?,NULL)",
            (th, user_id, now, now + RESET_TTL_SEC))
    return token


def consume_reset_token(token: str) -> str | None:
    """Валидирует и гасит токен (одноразовость). Возвращает user_id либо None."""
    import hashlib
    th = hashlib.sha256((token or "").encode()).hexdigest()
    now = time.time()
    with _lock, _conn() as c:
        r = c.execute(
            "SELECT user_id FROM password_resets WHERE token_hash=?"
            " AND used_at IS NULL AND expires_at > ?", (th, now)).fetchone()
        if not r:
            return None
        c.execute("UPDATE password_resets SET used_at=? WHERE token_hash=?",
                  (now, th))
    return r["user_id"]


def peek_reset_token(token: str) -> bool:
    """Проверяет действительность токена БЕЗ погашения — для GET-открытия
    страницы смены пароля из письма. Само сжатие происходит в POST."""
    import hashlib
    th = hashlib.sha256((token or "").encode()).hexdigest()
    now = time.time()
    with _conn() as c:
        r = c.execute(
            "SELECT 1 FROM password_resets WHERE token_hash=?"
            " AND used_at IS NULL AND expires_at > ?", (th, now)).fetchone()
    return r is not None


def drop_user_sessions(user_id: str) -> int:
    """Сбрасывает все сессии пользователя (после смены пароля / перевыпуска
    фактора). Возвращает число удалённых сессий."""
    with _lock, _conn() as c:
        cur = c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    return cur.rowcount or 0


# ---------------------------------------------------------------------------
# Сессии multi-stage state machine: password -> mfa -> authed
# ---------------------------------------------------------------------------
def create_session(user_id: str, stage: str, ip: str = "", ua: str = "",
                   ttl: float = 120.0, last_ua: str | None = None,
                   risk_score: int = 0) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex  # 256 бит энтропии
    now = time.time()
    with _lock, _conn() as c:
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        c.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)",
            (token, user_id, stage, ip, ua, last_ua, now, now + ttl, risk_score),
        )
    return token


def get_session(token: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
    if not r or r["expires_at"] < time.time():
        return None
    return dict(r)


def set_session_stage(token: str, stage: str, ttl: float | None = None) -> None:
    if ttl is None:
        ttl = AUTHED_TTL if stage == "authed" else 15 * 60
    with _lock, _conn() as c:
        c.execute("UPDATE sessions SET stage=?, expires_at=? WHERE token=?",
                  (stage, time.time() + ttl, token))


def touch_session(token: str, ttl: float = 15 * 60) -> None:
    """Продлевает короткую life-сессию промежуточной стадии (mfa).

    Нужно для сценария «первый вход»: пользователь ввёл верный пароль,
    получил ссылку/QR для привязки TOTP, установил приложение на телефон
    и вернулся подтвердить код — окно стадии не должно истечь за это время.
    """
    with _lock, _conn() as c:
        c.execute("UPDATE sessions SET expires_at=? WHERE token=? AND stage='mfa'",
                  (time.time() + ttl, token))


def drop_session(token: str) -> None:
    with _lock, _conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


# ---------------------------------------------------------------------------
# Аудит (journaling) — immutable append-only лог событий безопасности
# ---------------------------------------------------------------------------
def audit(event: str, actor: str = "", ip: str = "", success: bool = True,
          details: dict | None = None) -> None:
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO audit_log(ts, event, actor, ip, success, details) VALUES (?,?,?,?,?,?)",
            (time.time(), event, actor, ip, int(success),
             json.dumps(details or {}, ensure_ascii=False)),
        )


def recent_audit(limit: int = 50) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
