"""
main.py — сервис многоступенчатой аутентификации (MFA IdP), учебный стенд ВКР.

Стек: Python 3.12, FastAPI. Сессии — HttpOnly cookie + SameSite=Lax.

Поток аутентификации (state machine):
    [1] POST /login        пароль  -> stage=password->mfa (или block при high risk)
    [2] POST /verify-totp  TOTP    -> stage=mfa->authed
    [*] POST /verify-recovery резервный код вместо TOTP (потеря телефона)
Привязка фактора: /enroll/totp (QR otpauth://) -> /enroll/totp/confirm.

Запуск:  uvicorn app.main:app --reload
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from . import risk, security, store

SESSION_COOKIE = "mfa_session"
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(
    title="OrgMFA — система многоступенчатой аутентификации",
    description="Практическая реализация ВКР: MFA для информационной системы организации.",
    version="1.0.0",
)

# Фильтр шаблона: unix-время -> человекочитаемая дата для журнала
templates.env.filters["timestamp_fmt"] = lambda ts: time.strftime(
    "%d.%m %H:%M:%S", time.localtime(ts))


def client_ip(request: Request) -> str:
    xf = request.headers.get("x-forwarded-for")
    return (xf.split(",")[0].strip() if xf else request.client.host) or "?"


def ua(request: Request) -> str:
    return request.headers.get("user-agent", "")[:200]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def current_session(request: Request) -> dict | None:
    tok = request.cookies.get(SESSION_COOKIE)
    return store.get_session(tok) if tok else None


def user_of(session: dict) -> store.User | None:
    with store._conn() as c:
        r = c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return store.User.from_row(r) if r else None


def _redirect(request: Request, url: str, status: int = 303) -> RedirectResponse:
    resp = RedirectResponse(url, status_code=status)
    return resp


# --------------------------------------------------------------------------- #
# Страницы
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    s = current_session(request)
    if s and s["stage"] in ("authed", "setup"):
        u = user_of(s)
        if u is not None:
            return templates.TemplateResponse(
                request, "dashboard.html",
                {"user": u, "audit": store.recent_audit(15),
                 "setup": s["stage"] == "setup"})
    return _redirect(request, "/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"msg": ""})


@app.get("/mfa", response_class=HTMLResponse)
async def mfa_page(request: Request):
    s = current_session(request)
    if not s or s["stage"] != "mfa":
        return _redirect(request, "/login")
    return templates.TemplateResponse(request, "mfa.html")


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"msg": ""})


# --------------------------------------------------------------------------- #
# Регистрация
# --------------------------------------------------------------------------- #
@app.post("/register", response_class=HTMLResponse)
async def register(request: Request, login: str = Form(...),
                   full_name: str = Form(""), password: str = Form(...),
                   password2: str = Form(...)):
    ip = client_ip(request)
    if password != password2:
        msg = "Пароли не совпадают."
        return templates.TemplateResponse(request, "register.html", {"msg": msg}, status_code=400)
    try:
        store.create_user(login.strip(), password, full_name.strip())
    except ValueError as e:
        store.audit("user.register_failed", actor=login, ip=ip, success=False,
                    details={"reason": str(e)})
        return templates.TemplateResponse(request, "register.html", {"msg": str(e)}, status_code=400)
    store.audit("user.registered_ok", actor=login, ip=ip)
    return templates.TemplateResponse(
        request, "register.html",
        {"msg": "Учётная запись создана. Привяжите телефон к приложению-аутентификатору и войдите."},
    )


# --------------------------------------------------------------------------- #
# ШАГ 1: пароль + оценка риска
# --------------------------------------------------------------------------- #
@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, login: str = Form(...), password: str = Form(...)):
    ip, agent = client_ip(request), ua(request)

    if risk.rate_limited(ip):
        store.audit("auth.rate_limit", actor=login, ip=ip, success=False)
        return templates.TemplateResponse(
            request, "login.html",
            {"msg": "Слишком много попыток. Повторите позже (защита от перебора)."},
            status_code=429)

    u = store.get_user_by_login(login.strip())
    if u is None:
        # одинаковое сообщение и текст, чтобы не давать oracle' существования логина
        store.audit("auth.fail.unknown_user", actor=login, ip=ip, success=False)
        await _dummy_hash(password)
        return _login_error(request)

    if risk.is_locked(u):
        store.audit("auth.fail.locked", actor=u.login, ip=ip, success=False)
        return templates.TemplateResponse(
            request, "login.html",
            {"msg": f"Учётная запись временно заблокирована после {risk.MAX_FAILED} неудачных попыток."},
            status_code=403)

    ok, needs_rehash = security.verify_password(password, u.pass_hash)
    if not ok:
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("auth.fail.password", actor=u.login, ip=ip, success=False,
                    details={"failed_total": u.failed_attempts})
        return _login_error(request)

    # --- успешная 1-я ступень: сброс счётчика, rehash-upgrade ---
    u.failed_attempts = 0
    if needs_rehash:
        u.pass_hash = security.hash_password(password)
    store.update_user(u)

    # --- risk-based decision (step-up, не блокировка при верном пароле) ---
    last_login_ts = _last_success_ts(u.id)
    minutes_since = (time.time() - last_login_ts) / 60 if last_login_ts else None
    known_ua = _known_ua(u.id)
    score, reasons = risk.score_login(ip, agent, known_ua, u.failed_attempts, minutes_since)
    verdict = risk.decision(score)
    store.audit("auth.risk_score", actor=u.login, ip=ip,
                details={"score": score, "reasons": reasons, "decision": verdict})

    if not u.mfa_enabled:
        # Политика обязательной MFA: без привязанного фактора полный доступ
        # запрещён. Пользователю выдаётся временная сессия стадии "setup" —
        # в личном кабинете он может привязать TOTP (страницы MFA/API при этом
        # остаются недоступными).
        store.audit("auth.setup.required", actor=u.login, ip=ip, success=True)
        tok = store.create_session(u.id, "setup", ip, agent, ttl=10 * 60)
        resp = _redirect(request, "/")
        _set_cookie(resp, tok)
        return resp

    # Политика step-up: высокий риск — ужесточаем сессию (короткое время жизни,
    # обязательная ступень 2), но не отклоняем корректную аутентификацию.
    ttl = 60.0 if verdict != "allow" else 120.0
    tok = store.create_session(u.id, "mfa", ip, agent, ttl=ttl)
    resp = _redirect(request, "/mfa")
    _set_cookie(resp, tok)
    return resp


def _login_error(request: Request):
    return templates.TemplateResponse(
        request, "login.html",
        {"msg": "Неверный логин или пароль."},
        status_code=401)


async def _dummy_hash(pw: str) -> None:
    """Выравнивание времени ответа для неизвестного логина (anti user-enumeration)."""
    security.hash_password(pw or "x")


def _set_cookie(resp, token: str) -> None:
    resp.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, samesite="lax", secure=False,  # secure=True за HTTPS в проде
        max_age=8 * 3600, path="/",
    )


def _last_success_ts(user_id: str) -> float | None:
    with store._conn() as c:
        r = c.execute(
            "SELECT ts FROM audit_log WHERE event='auth.success' AND actor=("
            "SELECT login FROM users WHERE id=?) ORDER BY id DESC LIMIT 1",
            (user_id,)).fetchone()
    return r["ts"] if r else None


def _known_ua(user_id: str) -> str | None:
    with store._conn() as c:
        r = c.execute(
            "SELECT user_agent FROM sessions WHERE user_id=? AND stage='authed'"
            " ORDER BY created_at DESC LIMIT 1", (user_id,)).fetchone()
    return r["user_agent"] if r else None


# --------------------------------------------------------------------------- #
# ШАГ 2: TOTP / резервный код
# --------------------------------------------------------------------------- #
@app.post("/verify-totp")
async def verify_totp(request: Request, code: str = Form(...)):
    s = current_session(request)
    if not s or s["stage"] != "mfa":
        return JSONResponse({"error": "Сессия не найдена. Начните вход заново."}, 401)
    u = user_of(s)
    ip = client_ip(request)

    if u is None or u.totp_enc is None:
        return JSONResponse({"error": "Фактор не привязан."}, 403)

    code = code.replace(" ", "")
    seed = security.decrypt_secret(u.totp_enc)

    # защита от replay: один код принимается ровно один раз
    if risk.code_already_used(u.id, code):
        store.audit("auth.fail.replay", actor=u.login, ip=ip, success=False,
                    details={"code_suffix": code[-2:]})
        return JSONResponse({"error": "Код уже использован (защита от повторного воспроизведения)."}, 401)

    if not security.verify_totp(seed, code):
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("auth.fail.totp", actor=u.login, ip=ip, success=False,
                    details={"failed_total": u.failed_attempts})
        return JSONResponse({"error": "Неверный или просроченный код."}, 401)

    risk.remember_code(u.id, code)
    store.set_session_stage(s["token"], "authed")
    u.failed_attempts = 0
    store.update_user(u)
    store.audit("auth.success", actor=u.login, ip=ip,
                details={"factors": ["password", "totp"]})
    return JSONResponse({"ok": True, "redirect": "/"})


@app.post("/verify-recovery")
async def verify_recovery(request: Request, code: str = Form(...)):
    s = current_session(request)
    if not s or s["stage"] != "mfa":
        return JSONResponse({"error": "Сессия не найдена."}, 401)
    u = user_of(s)
    ip = client_ip(request)
    if u is None:
        return JSONResponse({"error": "Пользователь не найден."}, 401)

    h = security.hash_recovery_code(code)
    if u.recovery_hashes and any(
            security.constant_time_eq(h, stored) for stored in u.recovery_hashes):
        u.recovery_hashes.remove(h)          # одноразовость
        store.update_user(u)
        store.set_session_stage(s["token"], "authed")
        store.audit("auth.success_recovery", actor=u.login, ip=ip)
        return JSONResponse({"ok": True, "redirect": "/",
                             "warning": "Резервный код израсходован. Привяжите новый устройство."})
    store.audit("auth.fail.recovery", actor=u.login, ip=ip, success=False)
    return JSONResponse({"error": "Неверный резервный код."}, 401)


# --------------------------------------------------------------------------- #
# Привязка TOTP (enrollment)
# --------------------------------------------------------------------------- #
@app.post("/enroll/totp")
async def enroll_totp_start(request: Request):
    s = current_session(request)
    u = user_of(s) if s else None
    if u is None:
        # demo-hint: на стенде разрешаем привязку по логину+паролю из формы
        return JSONResponse({"error": "Требуется активная сессия после шага 1."}, 401)
    seed = security.generate_totp_secret()
    u.totp_enc = security.encrypt_secret(seed)
    u.recovery_hashes = [security.hash_recovery_code(c) for c in security.generate_recovery_codes()]
    u.mfa_enabled = False   # включится только после подтверждения кодом
    store.update_user(u)
    uri = security.totp_provisioning_uri(seed, u.login)
    totp_preview = security.totp_now(seed)  # для демо/отладки (в проде убрать!)
    store.audit("enroll.totp.started", actor=u.login, ip=client_ip(request))
    return JSONResponse({"otpauth_uri": uri, "secret_b32": _b32(seed),
                         "demo_current_code": totp_preview})


def _b32(b: bytes) -> str:
    import base64
    return base64.b32encode(b).decode().rstrip("=")


@app.post("/enroll/totp/confirm")
async def enroll_totp_confirm(request: Request, code: str = Form(...)):
    s = current_session(request)
    u = user_of(s) if s else None
    if u is None or u.totp_enc is None:
        return JSONResponse({"error": "Нет незавершённой привязки."}, 400)
    seed = security.decrypt_secret(u.totp_enc)
    if not security.verify_totp(seed, code.replace(" ", "")):
        return JSONResponse({"error": "Код не подошёл. Проверьте время на телефоне."}, 401)
    u.mfa_enabled = True
    store.update_user(u)
    store.audit("enroll.totp.confirmed", actor=u.login, ip=client_ip(request))
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------- #
# Завершение сеанса
# --------------------------------------------------------------------------- #
@app.post("/logout")
@app.get("/logout")
async def logout(request: Request):
    s = current_session(request)
    if s:
        store.drop_session(s["token"])
        store.audit("session.logout", actor=s["user_id"], ip=client_ip(request))
    resp = _redirect(request, "/login")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --------------------------------------------------------------------------- #
# API для интеграции демонстрационной ИС (проверка токена сессии)
# --------------------------------------------------------------------------- #
@app.get("/api/whoami")
async def whoami(request: Request):
    s = current_session(request)
    if not s or s["stage"] != "authed":
        return JSONResponse({"authenticated": False}, 401)
    u = user_of(s)
    return JSONResponse({"authenticated": True, "login": u.login,
                         "full_name": u.full_name, "mfa": u.mfa_enabled})


@app.on_event("startup")
async def startup() -> None:
    store.init_db()
    # демо-пользователь для защиты диссертационного показа
    if store.get_user_by_login("ivanov") is None:
        store.create_user("ivanov", "Demo2026!passw0rd", "Иванов А. П.")
