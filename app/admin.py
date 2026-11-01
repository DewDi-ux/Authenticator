"""
app.admin — модуль администратора OrgMFA (для корпоративной эксплуатации).

Разделение обязанностей (OWASP ASVS V1.4 / NIST SP 800-53 AC-6):
  * все маршруты смонтированы под префиксом /admin и требуют роль admin;
  * доступ только из доверенных сетей организации (risk.TRUSTED_SUBNET_PREFIXES);
  * административная сессия укорочена (ADMIN_SESSION_TTL) и требует step-up
    (повторного ввода пароля) перед каждым критическим действием;
  * step_up-сессия живёт ADMIN_STEPUP_TTL секунд, одноразовая (гасится после
    использования), выдаётся ТОЛЬКО после успешного пароля + TOTP;
  * каждое действие пишется в append-only audit_log (event='admin.*').

Запреты политики:
  * self-promotion — обычный пользователь не может выдать себе/другому роль;
    новый админ создается только bootstrap-переменной MFA_ADMIN_* при старте;
  * нельзя снять роль / деактивировать последнего активного администратора;
  * сброс фактора возможен только для учётки БЕЗ резервных кодов (иначе
    «потерявший телефон» сотрудник прошёл бы вход сам — оракул обходил бы
    верификацию личности); подтверждение личности — офлайн-процедура ИБ.

Публичные имена для app/main.py: admin_router, ADMIN_SESSION_TTL,
ADMIN_STEPUP_TTL, ADMIN_RISK_THRESHOLD.
"""

from __future__ import annotations

import json
import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pathlib import Path

from . import mailer, risk, security, store, uaparse

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Фильтр шаблона: unix-время -> человекочитаемая дата (журнал, сессии)
templates.env.filters["timestamp_fmt"] = lambda ts: time.strftime(
    "%d.%m %H:%M:%S", time.localtime(ts))

# --- параметры политики админ-зоны (см. docs/SECURITY.md, раздел 17) --------
ADMIN_SESSION_TTL = 2 * 3600.0   # короче обычной AUTHED_TTL (8 ч)
ADMIN_STEPUP_TTL = 120.0         # окно на повторный пароль после TOTP
ADMIN_RISK_THRESHOLD = 55        # порог «подозрительного» входа для алерта

router = APIRouter()


def _ip(request: Request) -> str:
    xf = request.headers.get("x-forwarded-for")
    return (xf.split(",")[0].strip() if xf else request.client.host) or "?"


def _page(request: Request, name: str, ctx: dict, status: int = 200):
    # error.html наследует standalone-макет (без админской навигации),
    # страницы консоли — общий admin_base с шапкой
    if name == "error.html":
        ctx = {**ctx, "standalone": True}
    return templates.TemplateResponse(request, name, ctx, status_code=status)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------
def _current(request: Request) -> tuple[dict | None, store.User | None]:
    tok = request.cookies.get("mfa_session")
    s = store.get_session(tok) if tok else None
    if not s:
        return None, None
    u = store.get_user_by_id(s["user_id"])
    return s, u


def _gate(request: Request) -> tuple[dict | None, store.User | None,
                                     Response | None]:
    """Единая проверка доступа к /admin/*. Возвращает (session, user, deny)."""
    s, u = _current(request)
    ip = _ip(request)
    if s is None:
        # Сессии нет (истекла/сброшена). Для админ-зоны логичнее вернуть на
        # /admin/login, а не на общий вход — раньше этот редирект и выглядел
        # как «выбросило из админки при действии над другим сотрудником».
        return s, u, RedirectResponse("/admin/login", status_code=303)
    if u is None or u.disabled:
        return s, u, RedirectResponse("/admin/login", status_code=303)
    if not u.is_admin:
        store.audit("admin.denied.not_admin", actor=u.login, ip=ip, success=False)
        return s, u, _page(request, "error.html", {
            "title": "Доступ запрещён",
            "message": "Раздел администратора доступен только учётным записям"
                       " с ролью admin."}, status=403)
    if not risk._in_trusted_network(ip):
        store.audit("admin.denied.untrusted_network", actor=u.login, ip=ip,
                    success=False)
        return s, u, _page(request, "error.html", {
            "title": "Доступ запрещён",
            "message": "Админ-консоль доступна только из доверенных сетей"
                       " организации."}, status=403)
    if s["stage"] == "setup":
        return s, u, _page(request, "error.html", {
            "title": "Требуется MFA", "message":
            "ПолитикаOrgMFA: доступ к админ-консоли только после полного"
            " двухфакторного входа. Привяжите TOTP в личном кабинете."},
            status=403)
    if s["stage"] != "authed":
        return s, u, RedirectResponse("/admin/login", status_code=303)
    return s, u, None


def _wants_json(request: Request) -> bool:
    """AJAX-запрос (fetch из консоли) vs обычная HTML-форма браузера."""
    accept = request.headers.get("accept", "")
    return "application/json" in accept


def _safe_admin_next(url: str) -> str:
    """Разрешаем редирект только на внутренние /admin GET-страницы."""
    if not url or not url.startswith("/admin") or url.startswith("//"):
        return "/admin"
    return url


def _get_next_url(path: str) -> str:
    """GET-адрес страницы для POST-маршрута действия.

    Страницы reauth/redirect должны указывать на HTML-представление (GET),
    а не на сам POST-эндпоинт: браузер откроет next методом GET и получил бы
    405 Method Not Allowed.
    """
    parts = [p for p in path.split("/") if p]  # ['admin','users','<uid>','disable',...]
    if len(parts) >= 3 and parts[0] == "admin" and parts[1] == "users":
        uid = parts[2]
        if len(parts) >= 4:          # действие над пользователем -> карточка
            return f"/admin/users/{uid}"
        if uid != "create":           # /admin/users или карточка -> список
            return "/admin/users"
    if len(parts) >= 2 and parts[0] == "admin" and parts[1] == "policy":
        return "/admin/policy"
    return "/admin"


def _reauth_denied(request: Request, next_url: str = "/admin",
                   login_url: str = "/admin/login") -> Response:
    """Отказ по step-up: для AJAX — JSON 401 reauth_required (иначе fetch
    молча следует редиректу на HTML-страницу reauth и падает на разборе
    HTML как JSON — «bad_response»); для форм — обычный 303.

    next_url всегда GET-страница: после подтверждения пароля редирект на
    POST-эндпоинт вызвал бы 405 Method Not Allowed.

    Если админская сессия уже истекла (cookie есть, записи нет/протухла),
    возвращаем не reauth, а session_expired: глупо предлагать повторный
    пароль от несуществующей сессии — UI пошлёт на /admin/login.
    """
    if _current(request)[0] is None:
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "error": "session_expired",
                 "message": "Административная сессия истекла. Войдите заново.",
                 "login_url": login_url},
                status_code=401)
        return RedirectResponse(login_url, status_code=303)
    next_url = _safe_admin_next(_get_next_url(next_url))
    if _wants_json(request):
        return JSONResponse(
            {"ok": False, "error": "reauth_required",
             "message": "Требуется повторное подтверждение (step-up).",
             "reauth_url": f"/admin/reauth?next={next_url}"},
            status_code=401)
    return RedirectResponse(login_url, status_code=303)


def _drop_target_sessions(t: store.User, actor_token: str) -> int:
    """Сброс сессий ЦЕЛЕВОЙ учётки t, но ВСЕГДА с сохранением текущей
    сессии администратора (actor_token).

    Токен админа уникален, поэтому даже при совпадении uid (админ действует
    над собственной учёткой) его собственная сессия не удаляется: раньше
    «Сбросить сессии» / деактивация / сброс фактора убивали и админскую
    сессию — браузер получал 303 на страницу, _gate не находил сессию и
    выбрасывал админа в общий вход (/login), что выглядело как «меня
    разлогинило при действии над другим сотрудником».
    """
    return store.drop_other_sessions(t.id, keep_token=actor_token)


def _require_stepup(request: Request) -> tuple[dict | None, store.User | None,
                                               Response | None]:
    """Для критических действий: stage=='step_up' + свежий timestamp.

    После повторного ввода пароля админ возвращается на GET-страницу,
    откуда выполнял действие (карточка пользователя / список), и повторяет
    его со свежим grant (TTL ADMIN_STEPUP_TTL).
    """
    s, u = _current(request)
    next_url = request.url.path or "/admin"
    if not next_url.startswith("/admin"):
        next_url = "/admin"
    if u is None or not u.is_admin or u.disabled:
        return s, u, _reauth_denied(request, next_url)
    # Stage «step_up» — это стадия ВХОДА (третий фактор при рискованном
    # логине), а не разрешение на действие. Раньше здесь требовался
    # s["stage"]=="step_up", из-за чего штатный authed-админ никогда не мог
    # выполнить критическое действие: запрос уходил на reauth, а POST
    # /admin/reauth ставил stage="step_up" с TTL 120 с — сессия умирала,
    # админа выбрасывало на /admin/login, действие не выполнялось.
    # Разрешение действия хранится отдельно: одноразовый grant (_stepup_grants).
    if s["stage"] != "authed":
        return s, u, _reauth_denied(request, next_url)
    st = _stepup_state(s["token"])
    if st is None or time.time() - st.get("granted_at", 0) > ADMIN_STEPUP_TTL:
        # не убиваем сессию целиком (иначе админ терял бы и authed-доступ):
        # просто снимаем протухший grant до повторного reauth
        _stepup_grants.pop(s["token"], None)
        return s, u, _reauth_denied(request, next_url)
    return s, u, None


# Служебное in-memory состояние step-up (одноразовость grant'а).
# В промышленной версии переносится в БД/Redis; очистка — по TTL.
_stepup_grants: dict[str, float] = {}   # session token -> granted_at ts


def _stepup_state(token: str) -> dict | None:
    ts = _stepup_grants.get(token)
    return {"granted_at": ts} if ts else None


def _grant_stepup(token: str, action: str) -> None:
    now = time.time()
    # чистим протухшие выдачи, чтобы словарь не рос бесконечно
    for k in [k for k, v in _stepup_grants.items() if now - v > 15 * 60]:
        _stepup_grants.pop(k, None)
    _stepup_grants[token] = now
    store.audit("admin.stepup.granted", actor="", ip="", details={
        "session": token[:12], "action": action})


# ---------------------------------------------------------------------------
# Вход администратора (тот же state machine, отдельная страница)
# ---------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, msg: str = ""):
    s, u, deny = _gate(request)
    if u and u.is_admin and s and s["stage"] == "authed":
        return RedirectResponse("/admin", status_code=303)
    return _page(request, "admin_login.html", {"msg": msg})


@router.post("/login", response_class=HTMLResponse)
async def admin_login(request: Request, login: str = Form(...),
                      password: str = Form(...)):
    ip = _ip(request)
    if risk.rate_limited(ip):
        return _page(request, "admin_login.html", {
            "msg": "Слишком много попыток. Повторите позже (защита от перебора)."
        }, status=429)
    if not risk._in_trusted_network(ip):
        # админ-зона доступна только из доверенных сетей организации
        store.audit("admin.login.untrusted_network", actor=login, ip=ip,
                    success=False)
        return _page(request, "error.html", {
            "title": "Доступ запрещён",
            "message": "Вход в админ-консоль разрешён только из доверенных"
                       " сетей организации."}, status=403)
    u = store.get_user_by_login(login.strip())
    if u is None or not u.is_admin:
        # анти-оракул: то же сообщение и время, что при неверном пароле
        await _dummy_hash(password)
        store.audit("admin.login.fail", actor=login, ip=ip, success=False)
        return _page(request, "admin_login.html",
                     {"msg": "Неверный логин или пароль."}, status=401)
    if u.disabled:
        store.audit("admin.login.disabled", actor=u.login, ip=ip, success=False)
        return _page(request, "admin_login.html",
                     {"msg": "Учётная запись деактивирована."}, status=403)
    if risk.is_locked(u):
        store.audit("admin.login.locked", actor=u.login, ip=ip, success=False)
        return _page(request, "admin_login.html", {
            "msg": f"Учётная запись заблокирована после {risk.MAX_FAILED}"
                   " неудачных попыток."}, status=403)
    ok, needs_rehash = security.verify_password(password, u.pass_hash)
    if not ok:
        was_locked = risk.is_locked(u)
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("admin.login.fail", actor=u.login, ip=ip, success=False,
                    details={"failed_total": u.failed_attempts})
        if u.email and not was_locked and u.failed_attempts >= risk.NOTIFY_FAILED_AT:
            subject, text, html = mailer.mail_failed_attempts(
                u.email, u.full_name, u.failed_attempts, ip,
                "Серия неудачных попыток входа в админ-консоль.")
            mailer.send_email(u.email, subject, text, html)
        return _page(request, "admin_login.html",
                     {"msg": "Неверный логин или пароль."}, status=401)
    u.failed_attempts = 0
    if needs_rehash:
        u.pass_hash = security.hash_password(password)
    store.update_user(u)
    if not u.mfa_enabled:
        store.audit("admin.login.setup_required", actor=u.login, ip=ip)
        return _page(request, "admin_login.html", {
            "msg": "Политика обязательной MFA: войдите через обычный вход,"
                   " привяжите TOTP в личном кабинете, затем возвращайтесь."},
            status=403)
    # оценка риска как в пользовательском входе; высокий риск -> step_up
    # (после TOTP потребуется резервный код — третий фактор для админ-зоны)
    last_ts = _last_admin_login_ts(u.login)
    minutes_since = (time.time() - last_ts) / 60 if last_ts else None
    agent = request.headers.get("user-agent", "")[:200]
    score, reasons = risk.score_login(ip, agent, None, 0, minutes_since)
    verdict = risk.decision(score)
    need_step_up = (risk.require_step_up(verdict, score, reasons)
                    and bool(u.recovery_hashes))
    stage = "step_up" if need_step_up else "mfa"
    tok = store.create_session(u.id, stage, ip, agent,
                               ttl=60.0 if verdict != "allow" else 120.0,
                               risk_score=score)
    resp = RedirectResponse("/admin/mfa", status_code=303)
    resp.set_cookie("mfa_session", tok, httponly=True, samesite="lax",
                    secure=False, max_age=8 * 3600, path="/")
    store.audit("admin.stage1.ok", actor=u.login, ip=ip,
                details={"score": score, "decision": verdict,
                         "reasons": reasons})
    return resp


async def _dummy_hash(pw: str) -> None:
    import asyncio
    await asyncio.sleep(0)
    security.hash_password(pw or "x")


def _last_admin_login_ts(login: str) -> float | None:
    """Время последнего успешного входа администратором (для признака
    «спящий аккаунт» в модели риска). Учитывает и обычные authed-входы."""
    with store._conn() as c:
        r = c.execute(
            "SELECT ts FROM audit_log WHERE actor=? AND ("
            "event='admin.login.success' OR event='auth.success'"
            ") ORDER BY id DESC LIMIT 1", (login,)).fetchone()
    return r["ts"] if r else None


@router.get("/mfa", response_class=HTMLResponse)
async def admin_mfa_page(request: Request):
    s, u = _current(request)
    if not s or s["stage"] not in ("mfa", "step_up"):
        return RedirectResponse("/admin/login", status_code=303)
    return _page(request, "admin_mfa.html", {})


@router.post("/mfa")
async def admin_mfa_verify(request: Request, code: str = Form(...),
                           recovery_code: str = Form("")):
    s, u = _current(request)
    ip = _ip(request)
    if not s or s["stage"] not in ("mfa", "step_up") or u is None or u.totp_enc is None:
        return JSONResponse({"error": "Сессия не найдена. Начните вход заново."}, 401)
    code = code.replace(" ", "")
    if risk.code_already_used(u.id, code):
        store.audit("admin.fail.replay", actor=u.login, ip=ip, success=False)
        return JSONResponse({"error": "Код уже использован."}, 401)
    seed = security.decrypt_secret(u.totp_enc)
    if not security.verify_totp(seed, code):
        risk.apply_failed_attempt(u, ip)
        store.update_user(u)
        store.audit("admin.fail.totp", actor=u.login, ip=ip, success=False)
        return JSONResponse({"error": "Неверный или просроченный код."}, 401)
    risk.remember_code(u.id, code)
    u.failed_attempts = 0
    store.update_user(u)

    # --- стадия step_up (высокий риск админ-входа): после TOTP требуется
    # третий фактор — ОДИН резервный код. Вход НЕ завершается без него. ---
    if s["stage"] == "step_up":
        rc = recovery_code.strip()
        if rc:
            h = security.hash_recovery_code(rc)
            if u.recovery_hashes and any(
                    security.constant_time_eq(h, stored)
                    for stored in u.recovery_hashes):
                u.recovery_hashes.remove(h)      # одноразовость
                store.update_user(u)
            else:
                store.audit("admin.fail.recovery", actor=u.login, ip=ip,
                            success=False)
                return JSONResponse({"ok": False, "step_up": True,
                                     "error": "Неверный резервный код."}, 401)
        if not risk.recovery_step_done(s["token"]):
            risk.mark_recovery_step_done(s["token"])
            store.audit("admin.step_up.recovery_ok", actor=u.login, ip=ip,
                        details={"remaining": len(u.recovery_hashes)})
            return JSONResponse({
                "ok": False, "step_up": True,
                "message": "Резервный код принят. Введите текущий TOTP-код "
                           "для завершения входа в админ-консоль."})
        # оба фактора пройдены — ниже завершаем вход (authed)

    store.set_session_stage(s["token"], "authed", ttl=ADMIN_SESSION_TTL)
    # Политика «одна активная сессия»: прочие сессии администратора
    # завершаются только сейчас — после полного успешного входа
    # (пароль + TOTP и, при стадии step_up, резервный код).
    dropped = store.drop_other_sessions(u.id, s["token"])
    factors = ["password", "totp"] + (["recovery"] if s["stage"] == "step_up" else [])
    store.audit("admin.login.success", actor=u.login, ip=ip,
                details={"factors": factors,
                         "other_sessions_terminated": dropped})
    # алерт policy: подозрительный вход администратора (score выше порога)
    if s.get("risk_score", 0) >= ADMIN_RISK_THRESHOLD:
        store.audit("admin.alert.risky_login", actor=u.login, ip=ip,
                    details={"score": s.get("risk_score")})
        if u.email:
            subject, text, html = mailer.mail_failed_attempts(
                u.email, u.full_name, 1, ip,
                "Обнаружен вход администратора с подозрительными признаками.")
            mailer.send_email(u.email, subject, text, html)
    return JSONResponse({"ok": True, "redirect": "/admin"})


# ---------------------------------------------------------------------------
# Step-up для критических действий
# ---------------------------------------------------------------------------
@router.get("/reauth", response_class=HTMLResponse)
async def reauth_page(request: Request, next: str = "/admin", msg: str = ""):
    s, u, deny = _gate(request)
    if deny:
        return deny
    return _page(request, "admin_reauth.html", {"next": next, "msg": msg})


@router.post("/reauth")
async def reauth(request: Request, password: str = Form(...),
                 next: str = Form("/admin")):
    s, u, deny = _gate(request)
    if deny:
        return deny
    ip = _ip(request)
    ok, _ = security.verify_password(password, u.pass_hash)
    if not ok:
        store.audit("admin.stepup.denied", actor=u.login, ip=ip, success=False,
                    details={"reason": "bad_password"})
        return _page(request, "admin_reauth.html",
                     {"next": next, "msg": "Неверный пароль."}, status=403)
    # next должен вести на GET-страницу: редирект 303 на POST-эндпоинт
    # (например, /admin/users/<uid>/drop-sessions) дал бы 405 Method Not Allowed
    next = _safe_admin_next(_get_next_url(next.split("?")[0]))
    _grant_stepup(s["token"], action=next)
    # ВАЖНО: разрешаем grant СВЕЖЕЙ authed-сессии. Раньше здесь ставился
    # stage="step_up" с ttl=ADMIN_STEPUP_TTL (120 с): админская сессия
    # умирала через 2 минуты после подтверждения пароля, и следующее
    # действие (или возврат на страницу) выбрасывало админа на /admin/login,
    # а цель (сессии сотрудника) оставалась нетронутой — grant умирал вместе
    # с записью сессии в БД. Теперь stage остаётся "authed", шаг подтверждён
    # отдельным одноразовым grant'ом с TTL ADMIN_STEPUP_TTL; сама сессия
    # продлевается стандартным ADMIN_SESSION_TTL.
    store.set_session_stage(s["token"], "authed", ttl=ADMIN_SESSION_TTL)
    store.audit("admin.stepup.ok", actor=u.login, ip=ip)
    resp = RedirectResponse(next, status_code=303)
    # cookie живёт дольше записи сессии — переставляем max_age актуальным
    # ADMIN_SESSION_TTL, чтобы браузер не «забыл» токен раньше времени
    resp.set_cookie("mfa_session", s["token"], httponly=True, samesite="lax",
                    secure=False, max_age=int(ADMIN_SESSION_TTL), path="/")
    return resp


# ---------------------------------------------------------------------------
# Дашборд / пользователи
# ---------------------------------------------------------------------------
@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    s, u, deny = _gate(request)
    if deny:
        return deny
    users = store.list_users()
    sessions = store.user_sessions()
    stats = {
        "users_total": len(users),
        "admins": sum(1 for x in users if x.is_admin and not x.disabled),
        "mfa_on": sum(1 for x in users if x.mfa_enabled),
        "locked": sum(1 for x in users
                      if risk.is_locked(x) or x.locked_until > time.time()),
        "disabled": sum(1 for x in users if x.disabled),
        "sessions": len(sessions),
    }
    recent_fail = store.audit_query(only_failed=True, limit=10)
    risky = [e for e in store.audit_query(event_prefix="auth.risk_score",
                                          limit=50)
             if json.loads(e["details"] or "{}").get("score", 0) >= 55]
    return _page(request, "admin_dashboard.html", {
        "me": u, "stats": stats, "recent_fail": recent_fail, "risky": risky[:10],
        "now": time.time()})


@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    s, u, deny = _gate(request)
    if deny:
        return deny
    rows = []
    for x in store.list_users():
        rows.append({
            "id": x.id, "login": x.login, "full_name": x.full_name,
            "email": x.email, "role": x.role, "disabled": x.disabled,
            "mfa_enabled": x.mfa_enabled, "has_factor": x.totp_enc is not None,
            "recovery_left": len(x.recovery_hashes),
            "failed": x.failed_attempts,
            "locked_until": x.locked_until,
            "locked_now": risk.is_locked(x),
        })
    return _page(request, "admin_users.html", {"me": u, "rows": rows,
                                               "now": time.time()})


@router.get("/users/{uid}", response_class=HTMLResponse)
async def user_detail(request: Request, uid: str):
    s, u, deny = _gate(request)
    if deny:
        return deny
    target = store.get_user_by_id(uid)
    if target is None:
        return _page(request, "error.html", {"title": "Нет такой учётки",
                                             "message": "user id не найден"}, 404)
    events = store.audit_query(actor=target.login, limit=50)
    sess = store.user_sessions(target.id)
    for r in sess:
        r["browser"] = uaparse.parse_browser(r.get("user_agent"))
        r["os"] = uaparse.parse_os(r.get("user_agent"))
    return _page(request, "admin_user_detail.html", {
        "me": u, "t": target, "events": events, "sessions": sess,
        "risk": risk, "now": time.time()})


# ---------------------------------------------------------------------------
# Действия администратора (все — через step-up)
# ---------------------------------------------------------------------------
@router.post("/users/{uid}/unlock")
async def unlock_user(request: Request, uid: str):
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    t.locked_until = 0.0
    t.failed_attempts = 0
    store.update_user(t)
    store.audit("admin.user.unlocked", actor=u.login, ip=_ip(request),
                details={"target": t.login})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message":
                         f"Блокировка снята: {t.login}. Пользователю отправлено уведомление."})


@router.post("/users/{uid}/disable")
async def disable_user(request: Request, uid: str, confirm: str = Form("")):
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    if t.id == u.id:
        return JSONResponse({"error": "self_disable_forbidden"}, 400)
    if confirm != t.login:
        return JSONResponse({"error": "confirm_mismatch",
                             "message": "Введите логин учётки для подтверждения."}, 400)
    if t.is_admin and store.admin_count() <= 1:
        return JSONResponse({"error": "last_admin"}, 400)
    t.disabled = True
    store.update_user(t)
    n = _drop_target_sessions(t, s["token"])
    store.audit("admin.user.disabled", actor=u.login, ip=_ip(request),
                details={"target": t.login, "sessions_dropped": n})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message":
                         f"Учётка {t.login} деактивирована, сброшено сессий: {n}."})


@router.post("/users/{uid}/enable")
async def enable_user(request: Request, uid: str):
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    t.disabled = False
    store.update_user(t)
    store.audit("admin.user.enabled", actor=u.login, ip=_ip(request),
                details={"target": t.login})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message": f"Учётка {t.login} активна."})


@router.post("/users/{uid}/drop-sessions")
async def drop_sessions(request: Request, uid: str):
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    n = _drop_target_sessions(t, s["token"])
    store.audit("admin.sessions.dropped", actor=u.login, ip=_ip(request),
                details={"target": t.login, "count": n})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message": f"Сброшено сессий: {n}."})


@router.post("/users/{uid}/reset-factor")
async def reset_factor(request: Request, uid: str, reason: str = Form(""),
                      notify: str = Form("")):
    """Инцидент-менеджмент MFA: сброс TOTP-фактора и перевыпуск резервных
    кодов. Ограничение anti-oracle: возможно только если у учётки НЕТ
    резервных кодов (иначе владелец обойдёт сброс через них). Личность
    подтверждается офлайн (паспорт/пропуск/сотрудник ИБ)."""
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    if t.recovery_hashes:
        return JSONResponse({"error": "has_recovery_codes", "message":
                             "У учётки есть неиспользованные резервные коды —"
                             " она может войти сама. Сброс фактора заблокирован"
                             " (anti-oracle). Дождитесь их расходования или"
                             " сначала отзовите коды."}, 400)
    codes = security.generate_recovery_codes()
    seed = security.generate_totp_secret()
    t.totp_enc = security.encrypt_secret(seed)
    t.recovery_hashes = [security.hash_recovery_code(c) for c in codes]
    t.mfa_enabled = False     # включится после подтверждения новым кодом
    store.update_user(t)
    _drop_target_sessions(t, s["token"])
    uri = security.totp_provisioning_uri(seed, t.login)
    qr = security.qr_png_data_uri(uri)
    link = f"{qr}"
    store.audit("admin.factor.reset", actor=u.login, ip=_ip(request),
                details={"target": t.login, "reason": reason[:120]})
    if notify == "on" and t.email:
        subject, text, html_body = mailer.mail_factor_reset(
            t.email, t.full_name or t.login, codes,
            f"{_base_url(request)}/login")
        mailer.send_email(t.email, subject, text, html_body)
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "otpauth_uri": uri, "qr_png": qr,
                         "recovery_codes": codes,
                         "message": "Фактор сброшен. Передайте QR и коды"
                                    " владельцу лично (или письмо, если"
                                    " включено уведомление)."})


@router.post("/users/{uid}/force-relogin")
async def force_relogin(request: Request, uid: str):
    """Принудительный повторный ввод фактора при компрометации устройства."""
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    n = _drop_target_sessions(t, s["token"])
    store.audit("admin.user.force_relogin", actor=u.login, ip=_ip(request),
                details={"target": t.login, "sessions_dropped": n})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message":
                         f"Сессии сброшены ({n}). Следующий вход — пароль + TOTP."})


@router.post("/users/create")
async def create_user(request: Request, login: str = Form(...),
                      full_name: str = Form(""), email: str = Form(""),
                      password: str = Form(...), role: str = Form("user"),
                      must_change: str = Form("")):
    """Создание учётной записи (в т.ч. сервисной). Роль admin выдавать
    запрещено: self-promotion закрыт политикой (bootstrap-only)."""
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    login = login.strip().lower()
    if role == "admin":
        store.audit("admin.user.role_grant_denied", actor=u.login,
                    ip=_ip(request), success=False,
                    details={"target": login, "reason": "self_promotion_policy"})
        return JSONResponse({"error": "role_admin_forbidden", "message":
                             "Новые администраторы создаются только"
                             " bootstrap-переменными окружения при старте"
                             " сервиса (защита от эскалации)."}, 403)
    try:
        store.create_user(login, password, full_name.strip(),
                          email.strip().lower(), role="user")
    except ValueError as e:
        return JSONResponse({"error": "validation", "message": str(e)}, 400)
    if must_change == "on":
        store.audit("admin.user.temp_password", actor=u.login, ip=_ip(request),
                    details={"target": login,
                             "policy": "first-login-change-recommended"})
    store.audit("admin.user.created", actor=u.login, ip=_ip(request),
                details={"target": login, "role": role})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message":
                         f"Учётка {login} создана. Передайте временный пароль"
                           " владельцу лично; при первом входе система"
                           " потребует привязку TOTP."})


@router.post("/users/{uid}/role")
async def change_role(request: Request, uid: str, role: str = Form("user")):
    """Изменение роли. Self-promotion запрещён; понижение последнего
    активного администратора запрещено."""
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    if role not in ("user", "admin"):
        return JSONResponse({"error": "bad_role"}, 400)
    t = store.get_user_by_id(uid)
    if t is None:
        return JSONResponse({"error": "not_found"}, 404)
    if role == "admin":
        store.audit("admin.role.grant_denied", actor=u.login, ip=_ip(request),
                    success=False, details={"target": t.login,
                                            "reason": "self_promotion_policy"})
        return JSONResponse({"error": "role_admin_forbidden", "message":
                             "Выдача роли admin из UI запрещена политикой"
                               "(только bootstrap при старте)."}, 403)
    if t.is_admin and store.admin_count() <= 1:
        return JSONResponse({"error": "last_admin"}, 400)
    t.role = role
    store.update_user(t)
    # роль сменилась — старые сессии невалидны, но сессия самого админа сохраняется
    _drop_target_sessions(t, s["token"])
    store.audit("admin.role.changed", actor=u.login, ip=_ip(request),
                details={"target": t.login, "to": role})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "message":
                         f"Роль {t.login}: {role}. Сессии пользователя сброшены."})


# ---------------------------------------------------------------------------
# Журнал / сессии / политика
# ---------------------------------------------------------------------------
@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request, q_event: str = "", q_actor: str = "",
                     failed_only: str = ""):
    s, u, deny = _gate(request)
    if deny:
        return deny
    rows = store.audit_query(
        event_prefix=q_event.strip() or None,
        actor=q_actor.strip() or None,
        only_failed=bool(failed_only), limit=200)
    return _page(request, "admin_audit.html", {
        "me": u, "rows": rows, "q_event": q_event, "q_actor": q_actor,
        "failed_only": failed_only})


@router.get("/audit/export.csv")
async def audit_export(request: Request):
    s, u, deny = _gate(request)
    if deny:
        return deny
    rows = store.audit_query(limit=5000)
    store.audit("admin.audit.exported", actor=u.login, ip=_ip(request),
                details={"rows": len(rows)})
    lines = ["ts,event,actor,ip,success,details"]
    for e in rows:
        d = str(e["details"] or "").replace('"', "'")
        lines.append(f'{int(e["ts"])},{e["event"]},{e["actor"]},{e["ip"]},'
                     f'{e["success"]},"{d}"')
    return Response("\n".join(lines), media_type="text/csv",
                    headers={"content-disposition":
                             'attachment; filename="orgmfa_audit.csv"'})


@router.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request):
    s, u, deny = _gate(request)
    if deny:
        return deny
    rows = store.user_sessions()
    # UA-строки разных Chromium-браузеров совпадают в начале — в UI выводим
    # отдельно распознанные браузер/ОС (полная строка — по наведению).
    # Важно: User-Agent подделывается, это отображение, а не идентификатор.
    for r in rows:
        r["browser"] = uaparse.parse_browser(r.get("user_agent"))
        r["os"] = uaparse.parse_os(r.get("user_agent"))
    return _page(request, "admin_sessions.html", {"me": u, "rows": rows,
                                                  "now": time.time()})


@router.get("/policy", response_class=HTMLResponse)
async def policy_page(request: Request):
    s, u, deny = _gate(request)
    if deny:
        return deny
    return _page(request, "admin_policy.html", {"me": u})


@router.get("/policy.json")
async def policy_json(request: Request):
    s, u, deny = _gate(request)
    if deny:
        return deny
    return JSONResponse({
        "risk": {"RISK_STEP_UP": risk.RISK_STEP_UP, "RISK_BLOCK": risk.RISK_BLOCK,
                 "STEP_UP_MIN_FACTORS": risk.STEP_UP_MIN_FACTORS,
                 "WORK_HOURS": list(risk.WORK_HOURS),
                 "TRUSTED_SUBNETS": list(risk.TRUSTED_SUBNET_PREFIXES)},
        "lockout": {"MAX_FAILED": risk.MAX_FAILED, "LOCKOUT_SEC": risk.LOCKOUT_SEC,
                    "NOTIFY_FAILED_AT": risk.NOTIFY_FAILED_AT},
        "rate_limit": {"RATE_LIMIT_MAX": risk.RATE_LIMIT_MAX,
                       "RATE_LIMIT_WINDOW": risk.RATE_LIMIT_WINDOW},
        "sessions": {"AUTHED_TTL": store.AUTHED_TTL,
                     "RESET_TTL_SEC": store.RESET_TTL_SEC,
                     "ADMIN_SESSION_TTL": ADMIN_SESSION_TTL,
                     "ADMIN_STEPUP_TTL": ADMIN_STEPUP_TTL},
        "password_policy_note": "argon2id m=64MiB t=3 p=4; минимум 10 симв.",
    })


@router.post("/policy")
async def policy_update(request: Request, step_up: str = Form(""),
                        block: str = Form(""), max_failed: str = Form(""),
                        lockout_min: str = Form(""), rate_max: str = Form(""),
                        work_start: str = Form(""), work_end: str = Form("")):
    """Runtime-настройка политик (для стенда). В промышленной версии значения
    живут в конфиге/БД и меняются через Change Management; изменения —
    только через step-up и пишутся в аудит."""
    s, u, deny = _require_stepup(request)
    if deny:
        return deny
    changed = {}
    def _set_int(name, val, obj, attr, lo, hi):
        nonlocal changed
        if val.strip() == "":
            return
        try:
            iv = int(val)
        except ValueError:
            raise HTTPException_(f"{name}: нужно целое число")
        if not (lo <= iv <= hi):
            raise HTTPException_(f"{name}: допустимо {lo}..{hi}")
        setattr(obj, attr, iv)
        changed[name] = iv
    try:
        _set_int("RISK_STEP_UP", step_up, risk, "RISK_STEP_UP", 1, 100)
        _set_int("RISK_BLOCK", block, risk, "RISK_BLOCK", 1, 100)
        _set_int("MAX_FAILED", max_failed, risk, "MAX_FAILED", 1, 100)
        _set_int("LOCKOUT_SEC", str(int(float(lockout_min) * 60)) if lockout_min.strip() else "",
                 risk, "LOCKOUT_SEC", 60, 86400)
        _set_int("RATE_LIMIT_MAX", rate_max, risk, "RATE_LIMIT_MAX", 1, 1000)
        if work_start.strip() and work_end.strip():
            a, b = int(work_start), int(work_end)
            if not (0 <= a < b <= 23):
                raise HTTPException_("Рабочие часы: 0<=старт<финиш<=23")
            risk.WORK_HOURS = (a, b)
            changed["WORK_HOURS"] = [a, b]
    except HTTPException_ as e:
        return JSONResponse({"error": "validation", "message": str(e)}, 400)
    store.audit("admin.policy.updated", actor=u.login, ip=_ip(request),
                details={"changed": changed})
    _consume_stepup(s["token"])
    return JSONResponse({"ok": True, "changed": changed,
                         "message": "Политики обновлены (runtime). Для"
                                    " постоянства перенесите значения в env/конфиг."})


class HTTPException_(Exception):
    pass


@router.post("/logout")
async def admin_logout(request: Request):
    s, u = _current(request)
    if s:
        store.drop_session(s["token"])
        risk.clear_step_up(s["token"])
        store.audit("admin.logout", actor=(u.login if u else ""), ip=_ip(request))
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("mfa_session")
    return resp


# ---------------------------------------------------------------------------
def _consume_stepup(token: str) -> None:
    """Step-up на действие одноразовый: гасим grant; сессия остаётся authed.

    Не меняем stage/TTL сессии: раньше здесь вызывался
    set_session_stage(..., ttl=ADMIN_SESSION_TTL), что для админа, вошедшего
    через обычный вход (cookie max_age 8 ч), укорачивало запись сессии до 2 ч
    и позже «тихо» выбрасывало его на /admin/login."""
    _stepup_grants.pop(token, None)
    risk.clear_step_up(token)


def _base_url(request: Request) -> str:
    import os
    return os.environ.get("MFA_BASE_URL", "").rstrip("/") or str(request.base_url).rstrip("/")
