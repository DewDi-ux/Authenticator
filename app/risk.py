"""
app.risk — оценка риска входа (adaptive/risk-based MFA).

Модель: каждое событие аутентификации получает score; при превышении
порога система требует дополнительную проверку или блокирует вход.
Реализованы проверки, детектирующие типичные векторы атак из модели угроз:
  * brute-force / credential stuffing  -> lockout + rate limit по IP;
  * смена устройства/подсети           -> повышенный риск;
  * вход в нерабочее время             -> повышенный риск (для орг. ИС);
  * replay одноразового кода           -> code reuse detector.
"""

from __future__ import annotations

import time

# Пороги (настраиваются политикой организации)
RISK_STEP_UP = 55   # ужесточение входа: после TOTP требуется третий фактор
RISK_BLOCK = 85     # максимальный verdict: step-up с минимальным TTL стадии
STEP_UP_MIN_FACTORS = 2   # шаг к ужесточению: не менее двух независимых причин

WORK_HOURS = (8, 19)          # рабочее время организации
TRUSTED_SUBNET_PREFIXES = ("127.", "10.", "192.168.")  # внутренние сети стенда


def _in_trusted_network(ip: str) -> bool:
    return ip.startswith(TRUSTED_SUBNET_PREFIXES) or ip == "::1"


def outside_work_hours(now: float | None = None) -> bool:
    """True, если текущий момент вне рабочих часов организации."""
    hour = time.localtime(now if now is not None else time.time()).tm_hour
    return not (WORK_HOURS[0] <= hour < WORK_HOURS[1])


# ---------------------------------------------------------------------------
# Дополнительные эвристики риска (пассивные, без изменения API score_login)
# ---------------------------------------------------------------------------
def is_proxy_or_tor(ip: str) -> bool:
    """Публичные Tor-exit-ноды (список обновляется по мере возможности —
    в проде лучше выносить в GeoIP/VPN-детектор сервис)."""
    _TOR_EXITS = ("185.220.", "162.247.74.", "171.25.193.", "104.244.76.")
    return ip.startswith(_TOR_EXITS)


def is_new_browser(ua: str | None) -> bool:
    """UA пустой или выглядит как автономный клиент/headless браузер — частый признак ботов."""
    if not ua:
        return True
    low = ua.lower()
    return any(k in low for k in ("headless", "phantomjs", "curl/", "wget/", "python-requests"))


def impossible_travel(prev_ip: str | None, prev_ts: float | None,
                      cur_ip: str, cur_ts: float | None = None,
                      min_km_per_hour: float = 800.0) -> bool:
    """Проверка на «невозможное перемещение»: два разных внешних IP за короткое время.
    
    Возвращает True, если между двумя входами с разных подсетей прошло слишком мало времени для физического перемещения.
    Для упрощения считаем, что разные /24 сети соответствуют разным городам (~1000 км), при минимальной скорости 800 км/ч это ~1.25 часа.
    """
    if not prev_ip or not prev_ts:
        return False
    # Если оба IP внутри доверенной сети — не считаем travel risk
    if _in_trusted_network(prev_ip) and _in_trusted_network(cur_ip):
        return False
    # Разные ли /24 подсети? (упрощённо: сравниваем первые три октета IPv4)
    def prefix24(ip: str) -> str:
        parts = ip.split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else ip
    if prefix24(prev_ip) == prefix24(cur_ip):
        return False
    # Прошло ли меньше MIN_HOURS_FOR_TRAVEL часов?
    cur_ts = cur_ts or time.time()
    hours_elapsed = (cur_ts - prev_ts) / 3600.0
    return hours_elapsed < (1000.0 / min_km_per_hour)


def score_login(ip: str, ua: str, known_ua: str | None, failed_recent: int,
                minutes_since_last: float | None = None,
                prev_ip: str | None = None, prev_ts: float | None = None) -> tuple[int, list[str]]:
    """Возвращает (score, причины). Каждая причина — строка для журнала.

    Калибровка весов (см. docs/integration.md, раздел «Модель угроз и риск»):
    штатный вход сотрудника (известное устройство, корпоративная подсеть,
    рабочее время) обязан давать allow; step-up включается только при
    сочетании двух и более независимых признаков риска либо при явном
    признаке перебора учётных данных. Это исключает ситуацию, когда
    «рискованный» вердикт выдаётся каждому пользователю на стенде.

    Дополнительные эвристики (опциональные аргументы — обратная совместимость):
      * proxy/Tor-IP;
      * headless/бот UA;
      * impossible travel (разные /24 за короткое время);
      * weekend login;
      * too many recent logins (>5 within 1h).
    """
    score, reasons = 0, []

    if failed_recent >= 3:
        # Явный признак перебора: вес подобран так, чтобы серия из
        # MAX_FAILED-1 неудачных попыток САМА (без учёта времени суток)
        # превышала порог step_up — это достаточное основание для
        # третьего фактора (OWASP ASVS V2.2.1).
        score += min(60, failed_recent * 15)
        reasons.append(f"series of failed attempts ({failed_recent})")

    if known_ua is None:
        score += 15
        reasons.append("new device/user-agent")
    elif known_ua != ua:
        score += 10
        reasons.append("user-agent changed")

    if not _in_trusted_network(ip):
        score += 10
        reasons.append("login from outside trusted network")

    if outside_work_hours():
        score += 8
        reasons.append("login outside business hours")

    if minutes_since_last is not None and minutes_since_last > 60 * 24 * 30:
        score += 8
        reasons.append("dormant account reactivation (>30 days)")

    # --- новые эвристики ---
    if is_proxy_or_tor(ip):
        score += 20
        reasons.append("proxy/tor IP detected")

    if is_new_browser(ua):
        score += 12
        reasons.append("bot/headless user-agent")

    if impossible_travel(prev_ip, prev_ts, ip):
        score += 25
        reasons.append("impossible travel between logins")

    # weekend login (суббота=5, воскресенье=6 в Python localtime)
    wd = time.localtime().tm_wday
    if wd in (5, 6):
        score += 6
        reasons.append("weekend login")

    # too many recent logins (проверяем через глобальный счётчик)
    # NB: учитываем частоту входов конкретного IP, а не общий счётчик всех
    # запросов score_login — иначе фоновые тестовые/админские входы с других
    # адресов ложно завышают риск обычным пользователям.
    now = time.time()
    _recent_logins[:] = [(t, i) for t, i in _recent_logins if now - t < 3600]
    same_ip_hits = [t for t, i in _recent_logins if i == ip]
    _recent_logins.append((now, ip))
    if len(same_ip_hits) + 1 > 5:
        score += 10
        reasons.append("too many recent logins (>5/hour)")

    return min(score, 100), reasons


# Глобальный список для отслеживания частоты входов: (ts, ip).
# В проде лучше Redis/скользящее окно по ключу ip/user_id.
_recent_logins: list[tuple[float, str]] = []


def _last_login_ip(user_id: str, before_ts: float | None = None) -> tuple[str | None, float | None]:
    """Возвращает (ip, ts) последнего успешного входа пользователя до before_ts.
    
    Используется для impossible travel проверки. Берём из audit_log события auth.success*.
    """
    from . import store  # ленивый импорт для избежания circular dependency
    with store._conn() as c:
        q = ("SELECT ip, ts FROM audit_log WHERE actor=("
             "SELECT login FROM users WHERE id=?) AND ("
             "event='auth.success' OR event='auth.success_recovery' OR "
             "event LIKE 'integration.auth.success%')")
        args = [user_id]
        if before_ts is not None:
            q += " AND ts < ?"
            args.append(before_ts)
        q += " ORDER BY id DESC LIMIT 1"
        r = c.execute(q, tuple(args)).fetchone()
    return (r["ip"], r["ts"]) if r else (None, None)


def decision(score: int) -> str:
    if score >= RISK_BLOCK:
        return "block"
    if score >= RISK_STEP_UP:
        return "step_up"
    return "allow"


# ---------------------------------------------------------------------------
# Защита от replay-атаки: одноразовый код не принимается дважды
# ---------------------------------------------------------------------------
_used_codes: dict[tuple[str, str], float] = {}   # (user_id, code) -> ts


def remember_code(user_id: str, code: str, window_sec: int = 90) -> None:
    _used_codes[(user_id, code)] = time.time() + window_sec


def code_already_used(user_id: str, code: str) -> bool:
    now = time.time()
    # очистка устаревших записей (окно TOTP + запас)
    for k in [k for k, exp in _used_codes.items() if exp < now]:
        _used_codes.pop(k, None)
    return (user_id, code) in _used_codes


# ---------------------------------------------------------------------------
# Rate limiting по IP (скользящее окно) — защита от перебора
# ---------------------------------------------------------------------------
_hits: dict[str, list[float]] = {}
RATE_LIMIT_MAX = 10          # не более 10 попыток...
RATE_LIMIT_WINDOW = 60.0     # ...за 60 секунд (OWASP ASVS V2.2.1)


def rate_limited(ip: str) -> bool:
    now = time.time()
    q = [t for t in _hits.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
    q.append(now)
    _hits[ip] = q
    return len(q) > RATE_LIMIT_MAX


# Lockout policy: 5 неудачных попыток -> блокировка аккаунта на 15 минут
MAX_FAILED = 5
LOCKOUT_SEC = 900
NOTIFY_FAILED_AT = 5   # порог почтового предупреждения владельца учётки
                       # (OWASP ASVS V2.2.1: уведомление о серии неудач)


def apply_failed_attempt(u, ip: str) -> None:
    u.failed_attempts += 1
    if u.failed_attempts >= MAX_FAILED:
        u.locked_until = time.time() + LOCKOUT_SEC


def is_locked(u, now: float | None = None) -> bool:
    return (now or time.time()) < u.locked_until


# ---------------------------------------------------------------------------
# Step-up при высоком риске: вердикт risk-движка ужесточает сеанс входа —
# после TOTP требуется ОДИН резервный код (третий фактор). Флаги пройденных
# ступеней хранятся на сессию; каждый фактор фиксируется ровно один раз,
# порядок прохождения (TOTP->код или код->TOTP) произвольный, повторного
# запроса уже пройденного фактора нет (защита от «зацикливания» step-up).
#
# Ограничение учебно-демонстрационного стенда: состояние живёт в памяти
# одного процесса uvicorn. При нескольких worker-процессах флаги и счётчики
# надо вынести в общее хранилище (Redis/БД) — см. docs/integration.md.
# ---------------------------------------------------------------------------
_stepup_totp_done: set[str] = set()
_stepup_recovery_done: set[str] = set()


def require_step_up(verdict: str, score: int, reasons: list[str] | None = None) -> bool:
    """Политика: step_up и block означают «нужен третий фактор».

    'block' в контексте уже корректно пройденной ступени 1 трактуется как
    максимальный step-up (см. README / docs/integration.md): вход не
    отклоняется молча, но без подтверждения третьим фактором не выполняется.

    Порог RISK_STEP_UP калиброван так, что одиночный бытовой признак
    (незнакомое устройство ИЛИ вход из вне доверенной подсети ИЛИ вход
    вне рабочего времени) НЕ ужесточает вход: шаг требуется либо при
    явном признаке перебора (серия неудачных попыток), либо при
    сочетании двух и более независимых причин риска.
    """
    if verdict not in ("step_up", "block"):
        return False
    if reasons and len(reasons) < STEP_UP_MIN_FACTORS:
        # порог формально превышен одной доминирующей причиной, но это
        # штатная ситуация (например, только «новый device») — не усложняем
        return any(r.startswith("series of failed attempts") for r in reasons)
    return True


def totp_step_done(token: str) -> bool:
    return token in _stepup_totp_done


def mark_totp_step_done(token: str) -> None:
    _stepup_totp_done.add(token)


def recovery_step_done(token: str) -> bool:
    return token in _stepup_recovery_done


def mark_recovery_step_done(token: str) -> None:
    _stepup_recovery_done.add(token)


def clear_step_up(token: str) -> None:
    _stepup_totp_done.discard(token)
    _stepup_recovery_done.discard(token)
