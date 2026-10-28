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

from fastapi import BackgroundTasks, FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from . import mailer, risk, security, store

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


# --- восстановление пароля («Забыли пароль?») --------------------------------
@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_page(request: Request, msg: str = ""):
    return templates.TemplateResponse(request, "forgot_password.html",
                                      {"msg": msg})


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request, background_tasks: BackgroundTasks,
                          email: str = Form("")):
    """Отправляет письмо со ссылкой смены пароля ТОЛЬКО если адрес привязан
    к существующей учётной записи. Внешний ответ при этом одинаков в обоих
    случаях — форма не работает оракулом существования почты."""
    ip = client_ip(request)
    email = email.strip().lower()
    u = store.get_user_by_email(email) if security.valid_email(email) else None
    if u is not None:
        token = store.create_reset_token(u.id)
        link = _reset_link(request, token)
        background_tasks.add_task(_notify_password_reset, u.email, u.full_name, link)
        store.audit("auth.reset_requested", actor=u.login, ip=ip,
                    details={"via": "email"})
    else:
        store.audit("auth.reset_requested_unknown", actor=email or "-", ip=ip,
                    success=False)
    return templates.TemplateResponse(
        request, "forgot_password.html",
        {"msg": "Если этот адрес привязан к учётной записи, на него отправлено "
                "письмо со ссылкой для смены пароля (ссылка одноразовая, "
                f"действует {store.RESET_TTL_SEC // 60} минут)."})


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_page(request: Request, token: str = "", error: str = ""):
    ok = bool(token) and store.peek_reset_token(token)
    if not ok:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"token": "", "msg": error or "Ссылка недействительна или истекла. "
                                          "Запросите восстановление ещё раз."},
            status_code=400)
    return templates.TemplateResponse(request, "reset_password.html",
                                      {"token": token, "msg": ""})


@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request, token: str = Form(...),
                         password: str = Form(...), password2: str = Form(...)):
    """Смена пароля по одноразовому токену из письма.

    Токен гасится ДО проверки сложности нового пароля — повторное использование
    ссылки невозможно даже при ошибке валидации (защита от «зombie»-токенов).
    Все активные сессии пользователя сбрасываются: старый пароль больше не
    должен держать сеансы живыми.
    """
    ip = client_ip(request)
    uid = store.consume_reset_token(token)
    if not uid:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"token": "", "msg": "Ссылка недействительна или уже использована. "
                                 "Запросите восстановление заново."},
            status_code=400)
    u = store.get_user_by_id(uid)
    if u is None:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"token": "", "msg": "Учётная запись не найдена."}, status_code=400)
    if password != password2:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"token": "", "msg": "Пароли не совпадают. Запросите новую ссылку."},
            status_code=400)
    errors = security.check_password_policy(password, u.login)
    if errors:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"token": "", "msg": "Новый пароль не подходит: " + "; ".join(errors) +
                       " Запросите новую ссылку."}, status_code=400)
    u.pass_hash = security.hash_password(password)
    u.failed_attempts = 0
    u.locked_until = 0.0          # раз легитимный владелец сменил пароль — снимаем lockout
    store.update_user(u)
    store.drop_user_sessions(u.id)
    store.audit("auth.password_reset_ok", actor=u.login, ip=ip)
    return templates.TemplateResponse(
        request, "login.html",
        {"msg": "Пароль изменён. Войдите с новым паролем и подтвердите вход "
                "TOTP-кодом."})


# --------------------------------------------------------------------------- #
# Почтовые уведомления (фоновые задачи — не тормозят ответ аутентификации)
# --------------------------------------------------------------------------- #
def _notify_failed_attempts(to: str, name: str, attempts: int, ip: str,
                            locked: bool) -> None:
    """Вызывается как background task после достижения порога неудач."""
    note = ("Учётная запись автоматически заблокирована на "
            f"{risk.LOCKOUT_SEC // 60} минут." if locked else
            "Если это продолжится, учётная запись будет временно заблокирована.")
    subject, text, html = mailer.mail_failed_attempts(to, name, attempts, ip, note)
    mailer.send_email(to, subject, text, html)


def _notify_password_reset(to: str, name: str, link: str) -> None:
    subject, text, html = mailer.mail_password_reset(
        to, name, link, store.RESET_TTL_SEC // 60)
    mailer.send_email(to, subject, text, html)


def _reset_link(request: Request, token: str) -> str:
    base = os.environ.get("MFA_BASE_URL", "").rstrip("/") or str(request.base_url).rstrip("/")
    return f"{base}/reset-password?token={token}"


# --------------------------------------------------------------------------- #
# Регистрация
# --------------------------------------------------------------------------- #
@app.post("/register", response_class=HTMLResponse)
async def register(request: Request, login: str = Form(...),
                   full_name: str = Form(""), password: str = Form(...),
                   password2: str = Form(...), email: str = Form("")):
    ip = client_ip(request)
    email = email.strip().lower()
    if password != password2:
        msg = "Пароли не совпадают."
        return templates.TemplateResponse(request, "register.html", {"msg": msg}, status_code=400)
    if not security.valid_email(email):
        return templates.TemplateResponse(
            request, "register.html",
            {"msg": "Укажите корректную электронную почту — на неё придут "
                    "уведомления о входах и ссылка восстановления пароля."},
            status_code=400)
    if store.get_user_by_email(email) is not None:
        # без раскрытия «занят чужой почтой» деталей для перебора:
        # одинаково нейтральное сообщение
        store.audit("user.register_failed", actor=login, ip=ip, success=False,
                    details={"reason": "email_taken"})
        return templates.TemplateResponse(
            request, "register.html",
            {"msg": "Не удалось создать учётную запись: проверьте логин и почту."},
            status_code=400)
    try:
        store.create_user(login.strip(), password, full_name.strip(), email)
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
async def login(request: Request, background_tasks: BackgroundTasks,
                login: str = Form(...), password: str = Form(...)):
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
        was_locked_before = risk.is_locked(u)
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("auth.fail.password", actor=u.login, ip=ip, success=False,
                    details={"failed_total": u.failed_attempts})
        # уведомление владельца почты: при достижении порога неудач и при
        # срабатывании блокировки (письмо уходит фоново — ответ не тормозится)
        if u.email and not was_locked_before and (
                u.failed_attempts >= risk.NOTIFY_FAILED_AT or
                (u.failed_attempts >= risk.MAX_FAILED and risk.is_locked(u))):
            background_tasks.add_task(
                _notify_failed_attempts, u.email, u.full_name,
                u.failed_attempts, ip, risk.is_locked(u))
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
    # (коды выданы при подтверждённой привязке TOTP). Политика порога —
    # в risk.require_step_up: одиночный бытовой признак вход не ужесточает.
    need_step_up = (risk.require_step_up(verdict, score, reasons)
                    and u.mfa_enabled and bool(u.recovery_hashes))
    # служебный флаг стенда для демонстрации step-up сценария на защите
    need_step_up = need_step_up or (_force_step_up(request) and u.mfa_enabled
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


def _force_step_up(request: Request) -> bool:
    """Служебный флаг учебного стенда для защиты диссертационного показа:
    X-Force-Step-Up: 1 имитирует высокий риск и включает стадию step_up без
    подделки признаков. В промышленной версии удалён/запрещён политикой."""
    return request.headers.get("x-force-step-up", "") in ("1", "true", "yes")


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
        # Высокий риск: фиксируем прохождение TOTP на сессии. Если резервный
        # код уже был принят ранее (пользователь начал с него) — вход завершён;
        # иначе ждём ОДИН резервный код. Повторного запроса TOTP не будет:
        # пройденный фактор больше не проверяется (устранено «зацикливание»,
        # расходующее два кода).
        risk.mark_totp_step_done(s["token"])
        if risk.recovery_step_done(s["token"]):
            store.set_session_stage(s["token"], "authed")
            risk.clear_step_up(s["token"])
            store.audit("auth.success", actor=u.login, ip=ip,
                        details={"factors": ["password", "recovery", "totp"],
                                 "step_up": True})
            return JSONResponse({"ok": True, "redirect": "/"})
        store.audit("auth.step_up.totp_ok", actor=u.login, ip=ip,
                    details={"reason": "risk-based step-up"})
        return JSONResponse({"ok": False, "step_up": True,
                             "message": "Вход с повышенным риском: TOTP принят. "
                                        "Для завершения входа введите один резервный код."})

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
        if s["stage"] == "step_up":
            # Резервный код принят. Если TOTP уже пройден — вход завершается
            # сразу (расход ОДНОГО кода). Иначе ждём текущий TOTP; повторный
            # резервный код в этой сессии не расходуется (флаги на сессию).
            if risk.totp_step_done(s["token"]):
                store.set_session_stage(s["token"], "authed")
                risk.clear_step_up(s["token"])
                store.audit("auth.success", actor=u.login, ip=ip,
                            details={"factors": ["password", "totp", "recovery"],
                                     "step_up": True,
                                     "remaining": len(u.recovery_hashes)})
                return JSONResponse({"ok": True, "redirect": "/",
                                     "warning": f"Вход выполнен. Резервных кодов осталось: "
                                                f"{len(u.recovery_hashes)}."})
            if risk.recovery_step_done(s["token"]):
                # этот тип кода уже засчитан в данной сессии — новый код не тратится
                return JSONResponse({
                    "ok": False, "step_up_pending": True,
                    "message": "Резервный код уже засчитан в этом входе. "
                               "Введите текущий TOTP-код из приложения."})
            risk.mark_recovery_step_done(s["token"])
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
async def enroll_totp_start(request: Request, password: str = Form("")):
    """Начало привязки TOTP.

    Разрешена только на setup-сессии (после верного пароля без MFA) либо в
    авторизованной сессии при ПОВТОРНОМ вводе пароля — иначе украденная cookie
    позволила бы подменить фактор молча. При перевыпуске старые резервные коды
    аннулируются; новые показываются пользователю ровно один раз.
    """
    s = current_session(request)
    u = user_of(s) if s else None
    if u is None:
        return JSONResponse({"error": "Требуется активная сессия после шага 1."}, 401)
    if s["stage"] == "authed":
        ok, _ = security.verify_password(password, u.pass_hash)
        if not ok:
            store.audit("enroll.totp.denied", actor=u.login,
                        ip=client_ip(request), success=False,
                        details={"reason": "password_confirmation_failed"})
            return JSONResponse({"error": "Для перевыпуска фактора подтвердите пароль."}, 403)
    elif s["stage"] != "setup":
        return JSONResponse({"error": "Привязка доступна сразу после входа или из личного кабинета."}, 403)
    seed = security.generate_totp_secret()
    codes = security.generate_recovery_codes()
    u.totp_enc = security.encrypt_secret(seed)
    # plaintext коды возвращаются ОДИН раз и нигде не сохраняются —
    # в БД идут только их хэши
    u.recovery_hashes = [security.hash_recovery_code(c) for c in codes]
    u.mfa_enabled = False   # включится только после подтверждения кодом
    store.update_user(u)
    uri = security.totp_provisioning_uri(seed, u.login)
    store.audit("enroll.totp.started", actor=u.login, ip=client_ip(request))
    # Никаких секретов и текущих TOTP-кодов в ответе: QR (otpauth:// URI) —
    # единственный канал передачи секрета устройству пользователя.
    # Ручной ввод Base32-секрета доступен на странице владельцу активной
    # setup-сессии отдельным запросом /enroll/totp/secret.
    return JSONResponse({"otpauth_uri": uri, "qr_png": security.qr_png_data_uri(uri),
                         "recovery_codes": codes})


@app.post("/recovery/regenerate")
async def recovery_regenerate(request: Request, password: str = Form(...)):
    """Перевыпуск резервных кодов из авторизованной сессии (с подтверждением
    паролем). Старые коды аннулируются, новые показываются один раз."""
    s = current_session(request)
    u = user_of(s) if s else None
    if not s or s["stage"] != "authed" or u is None:
        return JSONResponse({"error": "Требуется авторизованная сессия."}, 401)
    ok, _ = security.verify_password(password, u.pass_hash)
    if not ok:
        store.audit("recovery.regenerate.denied", actor=u.login,
                    ip=client_ip(request), success=False)
        return JSONResponse({"error": "Неверный пароль."}, 403)
    codes = security.generate_recovery_codes()
    u.recovery_hashes = [security.hash_recovery_code(c) for c in codes]
    store.update_user(u)
    store.audit("recovery.regenerated", actor=u.login, ip=client_ip(request))
    return JSONResponse({"ok": True, "recovery_codes": codes})


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
async def api_auth_login(request: Request, background_tasks: BackgroundTasks):
    """Шаг 1 для ИС: проверка пароля, оценка риска, создание stages-сессии.

    Вход: JSON {login, password}. Ответ: stage (mfa|step_up|setup), id сессии,
    TTL. При верном пароле сессия ещё НЕ авторизована — доступ к ИС выдаётся
    только после успешного /api/auth/totp (или /api/auth/recovery).
    Серия неудачных попыток порождает почтовое уведомление владельца учётки
    (фоновая задача, как в браузерном входе /login).
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
        was_locked_before = risk.is_locked(u)
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("integration.auth.fail", actor=u.login, ip=ip, success=False,
                    details={"failed_total": u.failed_attempts})
        if u.email and not was_locked_before and (
                u.failed_attempts >= risk.NOTIFY_FAILED_AT or
                (u.failed_attempts >= risk.MAX_FAILED and risk.is_locked(u))):
            background_tasks.add_task(
                _notify_failed_attempts, u.email, u.full_name,
                u.failed_attempts, ip, risk.is_locked(u))
        return JSONResponse({"error": "invalid_credentials"}, 401)

    last_login_ts = _last_success_ts(u.id)
    minutes_since = (time.time() - last_login_ts) / 60 if last_login_ts else None
    score, reasons = risk.score_login(ip, agent, _known_ua(u.id),
                                      u.failed_attempts, minutes_since)
    verdict = risk.decision(score)
    need_step_up = (risk.require_step_up(verdict, score, reasons)
                    and u.mfa_enabled and bool(u.recovery_hashes))
    # служебный флаг для интеграционных тестов/демо: X-Force-Step-Up: 1
    need_step_up = need_step_up or (_force_step_up(request) and u.mfa_enabled
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
        # Фиксируем TOTP на сессии; если резервный код уже принят — завершаем
        # вход, иначе ждём ОДИН резервный код (без повторного запроса TOTP).
        risk.mark_totp_step_done(tok)
        if risk.recovery_step_done(tok):
            store.set_session_stage(tok, "authed")
            risk.clear_step_up(tok)
            store.audit("integration.auth.success", actor=u.login, ip=ip,
                        details={"factors": ["password", "recovery", "totp"],
                                 "step_up": True})
            return JSONResponse({"ok": True, "result": "granted",
                                 "subject": u.login, "session": tok,
                                 "ttl": store.AUTHED_TTL})
        store.audit("integration.auth.step_up.totp_ok", actor=u.login, ip=ip)
        return JSONResponse({"ok": False, "step_up": True,
                             "message": "Требуется подтверждение одним резервным кодом."})

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

    if s["stage"] == "step_up":
        # Резервный код принят: если TOTP уже пройден — вход завершается сразу
        # (расход ОДНОГО кода); иначе ждём текущий TOTP. Повторный резервный
        # код в этой же сессии не расходуется.
        if risk.totp_step_done(tok):
            store.set_session_stage(tok, "authed")
            risk.clear_step_up(tok)
            store.audit("integration.auth.success", actor=u.login, ip=ip,
                        details={"factors": ["password", "totp", "recovery"],
                                 "step_up": True})
            return JSONResponse({"ok": True, "result": "granted", "subject": u.login,
                                 "session": tok, "ttl": store.AUTHED_TTL,
                                 "remaining_recovery_codes": len(u.recovery_hashes)})
        if risk.recovery_step_done(tok):
            return JSONResponse({"ok": False, "step_up_pending": True,
                                 "message": "Резервный код уже засчитан, требуется текущий TOTP.",
                                 "remaining_recovery_codes": len(u.recovery_hashes)})
        risk.mark_recovery_step_done(tok)
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
