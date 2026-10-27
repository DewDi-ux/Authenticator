"""
main.py — сервис многоступенчатой аутентификации (MFA IdP), учебный стенд ВКР.

Стек: Python 3.12, FastAPI. Сессии — HttpOnly cookie + SameSite=Lax.

Поток аутентификации (state machine):
    [1] POST /login        пароль + оценка риска -> stage "mfa"
                           (при риск-вердикте step_up/block -> stage "step_up":
                            после TOTP требуется дополнительный резервный код)
    [2] POST /verify-totp  TOTP    -> stage=mfa->authed (step_up->подтверждение)
    [*] POST /verify-recovery резервный код вместо TOTP (потеря телефона)
Привязка фактора: /enroll/totp (QR otpauth://) -> /enroll/totp/confirm.
Интеграция с ИС (сервисный контракт X-Service-Key): /api/auth/login,
/api/auth/totp, /api/auth/recovery, /api/introspect, /api/auth/logout —
см. docs/integration.md.

Запуск:  uvicorn app.main:app --reload
"""

from __future__ import annotations

import base64
import os
import time

from fastapi import FastAPI, Form, Request, Response
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
    if not s or s["stage"] not in ("mfa", "step_up"):
        return _redirect(request, "/login")
    return templates.TemplateResponse(
        request, "mfa.html", {"step_up": s["stage"] == "step_up"})


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

    # --- оценка риска ДО сброса счётчика неудачных попыток ---
    # Иначе серия из MAX_FAILED-1 неверных паролей «обнулялась» верным
    # паролем до вычисления score, и фактор перебора никогда не влиял на
    # решение. Теперь риск считается по накопленному счётчику.
    last_login_ts = _last_success_ts(u.id)
    minutes_since = (time.time() - last_login_ts) / 60 if last_login_ts else None
    score, reasons = risk.score_login(ip, agent, _known_ua(u.id),
                                      u.failed_attempts, minutes_since)
    verdict = risk.decision(score)
    store.audit("auth.risk_score", actor=u.login, ip=ip,
                details={"score": score, "reasons": reasons, "decision": verdict,
                         "failed_recent": u.failed_attempts})

    # --- высокий риск реально влияет на аутентификацию: verdict != allow
    # ужесточает сеанс (стадия step_up — вход возможен только после
    # подтверждения резервным кодом, см. /verify-totp и /verify-recovery).
    # Требование третьего фактора применимо только если он существует
    # (коды выданы при подтверждённой привязке TOTP).
    need_step_up = (risk.require_step_up(verdict, score) and u.mfa_enabled
                    and bool(u.recovery_hashes))

    # --- успешная 1-я ступень: сброс счётчика, rehash-upgrade ---
    u.failed_attempts = 0
    if needs_rehash:
        u.pass_hash = security.hash_password(password)
    store.update_user(u)

    # Учётный признак «перебор» уже отражён в score/verdict — не двойним его
    # константным штрафом за new device при первом же авторизованном входе.
    known_ua = _known_ua(u.id) or agent

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

    # Политика step-up: средний/высокий риск -> ужесточение сеанса.
    # стадия "step_up": ступень 2 (TOTP) обязательна, и после неё вход
    # завершается только подтверждением резервным кодом (третий фактор).
    # При verdict == "block" время жизни промежуточной стадии минимально.
    stage = "step_up" if need_step_up else "mfa"
    ttl = 60.0 if verdict != "allow" else 120.0
    tok = store.create_session(u.id, stage, ip, agent, ttl=ttl)
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
    # secure=False — осознанное ограничение учебного стенда (запуск по HTTP
    # на localhost). Перед эксплуатацией за HTTPS установить secure=True.
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
    if not s or s["stage"] not in ("mfa", "step_up"):
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
    u.failed_attempts = 0
    store.update_user(u)

    if s["stage"] == "step_up":
        # Высокий риск: TOTP пройден, но сеанс остаётся на ступени
        # подтверждения резервным кодом (третий фактор).
        store.audit("auth.step_up.totp_ok", actor=u.login, ip=ip,
                    details={"reason": "risk-based step-up"})
        return JSONResponse({"ok": False, "step_up": True,
                             "message": "Вход с высоким риском: подтвердите резервным кодом."})

    store.set_session_stage(s["token"], "authed")
    store.audit("auth.success", actor=u.login, ip=ip,
                details={"factors": ["password", "totp"]})
    return JSONResponse({"ok": True, "redirect": "/"})


@app.post("/verify-recovery")
async def verify_recovery(request: Request, code: str = Form(...)):
    s = current_session(request)
    if not s or s["stage"] not in ("mfa", "step_up"):
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
        if s["stage"] == "step_up" and not risk.step_up_done(s["token"]):
            # Step-up по риску: резервный код — ТРЕТИЙ фактор, он не заменяет
            # TOTP. Сессия остаётся на ступени 2 до ввода кода из приложения.
            risk.mark_step_up_done(s["token"])
            store.audit("auth.step_up.recovery_ok", actor=u.login, ip=ip,
                        details={"remaining": len(u.recovery_hashes)})
            return JSONResponse({
                "ok": False, "step_up_pending": True,
                "message": "Резервный код принят. Теперь введите текущий TOTP-код "
                           "из приложения для завершения входа.",
                "warning": f"Резервных кодов осталось: {len(u.recovery_hashes)}."})
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
    store.audit("enroll.totp.started", actor=u.login, ip=client_ip(request))
    # Никаких секретов и текущих кодов в ответе: QR (otpauth:// URI) —
    # единственный канал передачи секрета устройству пользователя.
    # Ручной ввод Base32-секрета доступен на странице владельцу активной
    # setup-сессии отдельным запросом /enroll/totp/secret.
    return JSONResponse({"otpauth_uri": uri, "qr_png": security.qr_png_data_uri(uri)})


@app.post("/enroll/totp/secret")
async def enroll_totp_secret(request: Request):
    """Base32-секрет для пользователей без камеры — по запросу, не по умолчанию.

    Разграничение: показ секрета — событие аудита; сам секрет не отдаётся
    вместе с QR, чтобы отладочная выдача не осталась в основном потоке
    привязки перед реальной эксплуатацией.
    """
    s = current_session(request)
    if not s or s["stage"] != "setup":
        return JSONResponse({"error": "Требуется активная сессия привязки."}, 401)
    u = user_of(s)
    if u is None or u.totp_enc is None:
        return JSONResponse({"error": "Нет незавершённой привязки."}, 400)
    store.audit("enroll.totp.secret_shown", actor=u.login, ip=client_ip(request))
    return JSONResponse({"secret_b32": _b32(security.decrypt_secret(u.totp_enc))})


def _b32(b: bytes) -> str:
    import base64
    return base64.b32encode(b).decode().rstrip("=")


@app.get("/enroll/totp/qr.png")
async def enroll_totp_qr(request: Request):
    """PNG QR-кода с otpauth:// URI текущей привязки.

    Альтернатива inline data-URI: картинку можно показать на отдельной
    странице/принтер; сканируется «Яндекс Ключом» без ручного ввода секрета.
    Секрет отдаётся только владельцу активной сессии привязки.
    """
    s = current_session(request)
    u = user_of(s) if s else None
    if u is None or u.totp_enc is None:
        return JSONResponse({"error": "Нет незавершённой привязки."}, 400)
    uri = security.totp_provisioning_uri(security.decrypt_secret(u.totp_enc), u.login)
    png = security.qr_png_data_uri(uri).split(",", 1)[1]  # снять префикс data:...;base64,
    return Response(content=base64.b64decode(png), media_type="image/png")


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
        risk.clear_step_up(s["token"])
        store.audit("session.logout", actor=s["user_id"], ip=client_ip(request))
    resp = _redirect(request, "/login")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --------------------------------------------------------------------------- #
# Контракт интеграции с ИС организации (полное описание — docs/integration.md)
# --------------------------------------------------------------------------- #
def _session_info(s: dict) -> dict:
    u = user_of(s)
    return {
        "subject": u.login if u else None,
        "full_name": u.full_name if u else None,
        "stage": s["stage"],
        "authenticated": s["stage"] == "authed",
        "factors": ["password", "totp"] if s["stage"] == "authed" else [],
        "risk_score": s["risk_score"],
        "ip": s["ip"],
        "expires_at": s["expires_at"],
    }


@app.get("/api/whoami")
async def whoami(request: Request):
    """Проверка текущей cookie-сессии (браузерный сценарий демонстрационной ИС)."""
    s = current_session(request)
    if not s or s["stage"] != "authed":
        return JSONResponse({"authenticated": False}, 401)
    u = user_of(s)
    return JSONResponse({"authenticated": True, "login": u.login,
                         "full_name": u.full_name, "mfa": u.mfa_enabled})


INTEGRATION_KEY_ENV = "MFA_INTEGRATION_KEY"


def _check_service_key(request: Request) -> bool:
    """Сервисный ключ ИС (X-Service-Key). Для стенда задаётся переменной
    окружения; в промышленной версии заменяется mTLS/OIDC-токеном."""
    key = os.environ.get(INTEGRATION_KEY_ENV)
    if not key:
        return False          # интеграция не включена на стенде
    return security.constant_time_eq(request.headers.get("x-service-key", ""), key)


def _require_service_key(request: Request) -> JSONResponse | None:
    if not _check_service_key(request):
        store.audit("integration.denied", ip=client_ip(request), success=False)
        return JSONResponse(
            {"error": "Интеграция не настроена или неверный X-Service-Key "
                      "(переменная окружения MFA_INTEGRATION_KEY). "
                      "См. docs/integration.md."}, 403)
    return None


@app.post("/api/auth/login")
async def api_auth_login(request: Request):
    """Шаг 1 для ИС: проверка пароля, оценка риска, создание stages-сессии.

    Вход: JSON {login, password}. Ответ: stage (mfa|step_up|setup), id сессии,
    TTL. При верном пароле сессия ещё НЕ авторизована — доступ к ИС выдаётся
    только после успешного /api/auth/totp (или /api/auth/recovery).
    """
    denied = _require_service_key(request)
    if denied:
        return denied
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Ожидается JSON."}, 400)
    login = str(body.get("login", "")).strip()
    password = str(body.get("password", ""))
    ip = client_ip(request)
    agent = ua(request)[:200]

    if risk.rate_limited(ip):
        store.audit("integration.auth.rate_limit", actor=login, ip=ip, success=False)
        return JSONResponse({"error": "rate_limited"}, 429)

    u = store.get_user_by_login(login)
    if u is None:
        await _dummy_hash(password)
        store.audit("integration.auth.fail", actor=login, ip=ip, success=False)
        return JSONResponse({"error": "invalid_credentials"}, 401)
    if risk.is_locked(u):
        store.audit("integration.auth.locked", actor=u.login, ip=ip, success=False)
        return JSONResponse({"error": "account_locked"}, 403)

    ok, needs_rehash = security.verify_password(password, u.pass_hash)
    if not ok:
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("integration.auth.fail", actor=u.login, ip=ip, success=False,
                    details={"failed_total": u.failed_attempts})
        return JSONResponse({"error": "invalid_credentials"}, 401)

    score, reasons = risk.score_login(ip, agent, _known_ua(u.id),
                                      u.failed_attempts, None)
    verdict = risk.decision(score)
    need_step_up = (risk.require_step_up(verdict, score) and u.mfa_enabled
                    and bool(u.recovery_hashes))

    u.failed_attempts = 0
    if needs_rehash:
        u.pass_hash = security.hash_password(password)
    store.update_user(u)

    if not u.mfa_enabled:
        tok = store.create_session(u.id, "setup", ip, agent, ttl=10 * 60,
                                   risk_score=score)
        store.audit("integration.auth.stage1", actor=u.login, ip=ip,
                    details={"stage": "setup", "score": score, "reasons": reasons})
        return JSONResponse({"stage": "setup", "session": tok, "ttl": 600,
                             "risk": {"score": score, "decision": verdict,
                                      "reasons": reasons}})

    tok = store.create_session(u.id, "step_up" if need_step_up else "mfa",
                               ip, agent, ttl=60.0 if verdict != "allow" else 120.0,
                               risk_score=score)
    store.audit("integration.auth.stage1", actor=u.login, ip=ip,
                details={"stage": "step_up" if need_step_up else "mfa",
                         "score": score, "reasons": reasons})
    return JSONResponse({"stage": "step_up" if need_step_up else "mfa",
                         "session": tok,
                         "ttl": 60.0 if verdict != "allow" else 120.0,
                         "risk": {"score": score, "decision": verdict,
                                  "reasons": reasons}})


@app.post("/api/auth/totp")
async def api_auth_totp(request: Request):
    """Шаг 2 для ИС: проверка TOTP по session_id. На стадии step_up требует
    дополнительно резервный код (см. ответ step_up=true)."""
    denied = _require_service_key(request)
    if denied:
        return denied
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Ожидается JSON."}, 400)
    tok = str(body.get("session", ""))
    code = str(body.get("code", "")).replace(" ", "")
    s = store.get_session(tok)
    if not s or s["stage"] not in ("mfa", "step_up"):
        return JSONResponse({"error": "session_not_found"}, 401)
    u = user_of(s)
    ip = client_ip(request)
    if u is None or u.totp_enc is None:
        return JSONResponse({"error": "factor_not_enrolled"}, 403)

    if risk.code_already_used(u.id, code):
        store.audit("integration.auth.fail.replay", actor=u.login, ip=ip, success=False)
        return JSONResponse({"error": "code_replay_detected"}, 401)

    seed = security.decrypt_secret(u.totp_enc)
    if not security.verify_totp(seed, code):
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("integration.auth.fail.totp", actor=u.login, ip=ip, success=False)
        return JSONResponse({"error": "invalid_code"}, 401)

    risk.remember_code(u.id, code)
    u.failed_attempts = 0
    store.update_user(u)

    if s["stage"] == "step_up":
        store.audit("integration.auth.step_up.totp_ok", actor=u.login, ip=ip)
        return JSONResponse({"ok": False, "step_up": True,
                             "message": "Требуется подтверждение резервным кодом."})

    store.set_session_stage(tok, "authed")
    store.audit("integration.auth.success", actor=u.login, ip=ip,
                details={"factors": ["password", "totp"]})
    return JSONResponse({"ok": True, "result": "granted",
                         "subject": u.login, "session": tok,
                         "ttl": store.AUTHED_TTL})


@app.post("/api/auth/recovery")
async def api_auth_recovery(request: Request):
    """Шаг 2 (альтернатива) для ИС: резервный код вместо TOTP."""
    denied = _require_service_key(request)
    if denied:
        return denied
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Ожидается JSON."}, 400)
    tok = str(body.get("session", ""))
    code = str(body.get("code", ""))
    s = store.get_session(tok)
    if not s or s["stage"] not in ("mfa", "step_up"):
        return JSONResponse({"error": "session_not_found"}, 401)
    u = user_of(s)
    ip = client_ip(request)
    if u is None:
        return JSONResponse({"error": "session_not_found"}, 401)

    h = security.hash_recovery_code(code)
    if not (u.recovery_hashes and any(
            security.constant_time_eq(h, stored) for stored in u.recovery_hashes)):
        store.audit("integration.auth.fail.recovery", actor=u.login, ip=ip, success=False)
        return JSONResponse({"error": "invalid_code"}, 401)

    u.recovery_hashes.remove(h)
    store.update_user(u)

    if s["stage"] == "step_up" and not risk.step_up_done(tok):
        risk.mark_step_up_done(tok)
        store.audit("integration.auth.step_up.recovery_ok", actor=u.login, ip=ip)
        return JSONResponse({"ok": False, "step_up_pending": True,
                             "message": "Резервный код принят, требуется текущий TOTP.",
                             "remaining_recovery_codes": len(u.recovery_hashes)})

    store.set_session_stage(tok, "authed")
    store.audit("integration.auth.success_recovery", actor=u.login, ip=ip,
                details={"remaining": len(u.recovery_hashes)})
    return JSONResponse({"ok": True, "result": "granted", "subject": u.login,
                         "session": tok, "ttl": store.AUTHED_TTL,
                         "remaining_recovery_codes": len(u.recovery_hashes)})


@app.get("/api/introspect")
async def api_introspect(request: Request, session: str = ""):
    """Интроспекция сессии аутентификации для ИС (аналог RFC 7662).

    ИС передаёт session_id, полученный в шаге 2; сервис возвращает субъекта,
    пройденные факторы, оценку риска и факт истечения. Ответ может кэшироваться
    ИС не дольше оставшегося TTL.
    """
    denied = _require_service_key(request)
    if denied:
        return denied
    s = store.get_session(session)
    if not s:
        return JSONResponse({"active": False}, 200)
    return JSONResponse({"active": s["stage"] == "authed", **_session_info(s)})


@app.post("/api/auth/logout")
async def api_auth_logout(request: Request):
    """Завершение сеанса по инициативе ИС (single logout для данной сессии)."""
    denied = _require_service_key(request)
    if denied:
        return denied
    try:
        body = await request.json()
    except Exception:
        body = {}
    tok = str(body.get("session", ""))
    if store.get_session(tok):
        store.drop_session(tok)
        risk.clear_step_up(tok)
        store.audit("integration.session.logout", ip=client_ip(request))
    return JSONResponse({"ok": True})


@app.on_event("startup")
async def startup() -> None:
    store.init_db()
    # демо-пользователь для защиты диссертационного показа
    if store.get_user_by_login("ivanov") is None:
        store.create_user("ivanov", "Demo2026!passw0rd", "Иванов А. П.")
