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
RISK_MEDIUM = 30   # требовать обязательный второй фактор даже если MFA "опциональна"
RISK_HIGH = 70     # блокировать до подтверждения администратором / step-up

WORK_HOURS = (8, 19)          # рабочее время организации
TRUSTED_SUBNET_PREFIX = "127."  # внутренняя сеть организации (демо: localhost)


def score_login(ip: str, ua: str, known_ua: str | None, failed_recent: int,
                minutes_since_last: float | None) -> tuple[int, list[str]]:
    """Возвращает (score, причины). Каждая причина — строка для журнала."""
    score, reasons = 0, []

    if failed_recent >= 3:
        score += min(40, failed_recent * 8)
        reasons.append(f"series of failed attempts ({failed_recent})")

    if known_ua is None:
        score += 20
        reasons.append("new device/user-agent")
    elif known_ua != ua:
        score += 15
        reasons.append("user-agent changed")

    if not ip.startswith(TRUSTED_SUBNET_PREFIX):
        score += 10
        reasons.append("login from outside trusted network")

    hour = time.localtime().tm_hour
    if not (WORK_HOURS[0] <= hour < WORK_HOURS[1]):
        score += 10
        reasons.append("login outside business hours")

    if minutes_since_last is not None and minutes_since_last > 60 * 24 * 30:
        score += 10
        reasons.append("dormant account reactivation (>30 days)")

    return min(score, 100), reasons


def decision(score: int) -> str:
    if score >= RISK_HIGH:
        return "block"
    if score >= RISK_MEDIUM:
        return "step_up"      # обязательный MFA + уведомление пользователя
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


def apply_failed_attempt(u, ip: str) -> None:
    u.failed_attempts += 1
    if u.failed_attempts >= MAX_FAILED:
        u.locked_until = time.time() + LOCKOUT_SEC


def is_locked(u, now: float | None = None) -> bool:
    return (now or time.time()) < u.locked_until
