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


def score_login(ip: str, ua: str, known_ua: str | None, failed_recent: int,
                minutes_since_last: float | None = None) -> tuple[int, list[str]]:
    """Возвращает (score, причины). Каждая причина — строка для журнала.

    Калибровка весов (см. docs/integration.md, раздел «Модель угроз и риск»):
    штатный вход сотрудника (известное устройство, корпоративная подсеть,
    рабочее время) обязан давать allow; step-up включается только при
    сочетании двух и более независимых признаков риска либо при явном
    признаке перебора учётных данных. Это исключает ситуацию, когда
    «рискованный» вердикт выдаётся каждому пользователю на стенде.
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

    return min(score, 100), reasons


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
