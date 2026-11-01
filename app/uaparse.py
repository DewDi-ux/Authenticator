"""
app.uaparse — лёгкий распознаватель браузеров из User-Agent (для интерфейса).

Назначение: в таблице активных сессий строки UA Chrome/Opera/Edge/Yandex на
Chromium почти идентичны в первых символах, поэтому обрезанный фрагмент
выглядит одинаково для разных браузеров. Модуль вытаскивает человекочитаемое
имя браузера и платформу, чтобы администратор видел различия явно.

Ограничение (фиксируем в UI): User-Agent — клиентский заголовок, он легко
подделывается. Распознанное имя подходит только для отображения, но НЕ как
надёжный идентификатор устройства; для моделей риска UA остаётся эвристикой.
"""

from __future__ import annotations


def parse_browser(ua: str | None) -> str:
    """Возвращает короткое имя браузера по строке User-Agent.

    Порядок проверок важен: клоны Chromium (Opera, Яндекс, Edge, Samsung…)
    содержат в UA и «Chrome/…», поэтому их надо тестировать раньше Chrome.
    """
    if not ua:
        return "—"
    low = ua.lower()

    # --- мобильные / встроенные ---
    if "edg/" in low or "edga/" in low or "edgios/" in low:
        return "Edge"
    if "opr/" in low or "opera" in low:
        return "Opera"
    if "yamapc" in low or "yabrowser" in low:          # Яндекс.Браузер
        return "Яндекс"
    if "samsungbrowser" in low:
        return "Samsung Internet"
    if "ucbrowser" in low:
        return "UC Browser"
    if "firefox/" in low or "fxios/" in low:
        return "Firefox"
    if "crios/" in low:
        return "Chrome"
    if "chrome/" in low or "chromium/" in low:
        return "Chrome"
    if "safari/" in low:
        return "Safari"
    if "curl/" in low:
        return "curl"
    if "python-httpx" in low or "python-requests" in low:
        return "HTTP-клиент"
    if "bot" in low or "spider" in low or "crawler" in low:
        return "Бот"
    return "Неизвестный"


def parse_os(ua: str | None) -> str:
    """Возвращает короткое имя ОС/платформы по строке User-Agent."""
    if not ua:
        return "—"
    low = ua.lower()
    if "windows nt" in low:
        return "Windows"
    if "iphone" in low or "ipad" in low or "ipod" in low:
        return "iOS"
    if "mac os x" in low or "darwin" in low:
        return "macOS"
    if "android" in low:
        return "Android"
    if "linux" in low or "x11" in low:
        return "Linux"
    return "Неизвестно"
