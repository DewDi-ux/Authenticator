"""
app.mailer — отправка писем пользователю (восстановление пароля,
уведомления о подозрительной активности).

Транспорт: Resend API (https://api.resend.com/emails) — HTTPS + Bearer-токен,
SMTP не требуется. Ключ берётся из переменной окружения RESEND_API_KEY,
отправитель — из MAIL_FROM (по умолчанию onboarding@resend.dev — песочный
домен Resend для тестов без верификации домена).

Письма отправляются ФОНОВЫМ ЗАДАЧЕМ FastAPI (starlette BackgroundTasks),
чтобы сетевая задержка не блокировала ответ аутентификации; ошибка доставки
фиксируется в журнале аудита и НЕ влияет на результат входа.

Если RESEND_API_KEY не задан, включается режим стенда "console": письмо
не уходит в сеть, а записывается в журнал аудита (детали доставки при этом
не светятся в HTTP-ответе). Для локальных прогонов pytest это безопасный
вариант по умолчанию.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import store

API_URL = "https://api.resend.com/emails"
API_KEY_ENV = "RESEND_API_KEY"
FROM_ENV = "MAIL_FROM"
DEFAULT_FROM = "OrgMFA <onboarding@resend.dev>"
TIMEOUT_SEC = 10


def is_configured() -> bool:
    """True, если задан ключ Resend (реальная доставка), иначе — console-стенд."""
    return bool(os.environ.get(API_KEY_ENV))


def sender() -> str:
    return os.environ.get(FROM_ENV) or DEFAULT_FROM


def send_email(to: str, subject: str, text_body: str,
               html_body: str | None = None) -> bool:
    """Отправка одного письма. Возвращает True при успехе.

    Никогда не бросает исключение наружу — вызывающий код (обработчик входа)
    не должен падать из-за проблем почты.
    """
    api_key = os.environ.get(API_KEY_ENV)
    payload = {
        "from": sender(),
        "to": [to],
        "subject": subject,
        "text": text_body,
    }
    if html_body:
        payload["html"] = html_body

    if not api_key:
        # стендовый режим: без внешнего трафика, факт — в аудит
        store.audit("mail.console", actor=to, success=True,
                    details={"subject": subject})
        print(f"[mailer:console] to={to} subject={subject!r}")
        return True

    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            ok = 200 <= resp.status < 300
        store.audit("mail.sent", actor=to, success=ok,
                    details={"subject": subject})
        return ok
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
        store.audit("mail.failed", actor=to, success=False,
                    details={"subject": subject, "error": str(e)[:200]})
        return False


# ---------------------------------------------------------------------------
# Шаблоны писем (plain text + простой HTML)
# ---------------------------------------------------------------------------
def _wrap(text: str) -> str:
    paras = "".join(
        f"<p style='font-family:Arial,sans-serif;font-size:14px;color:#0f172a'>{ln}</p>"
        for ln in text.split("\n") if ln.strip())
    return (f"<div style='max-width:560px;margin:0 auto;padding:16px'>"
            f"{paras}</div>")


def mail_password_reset(to: str, name: str, link: str, ttl_min: int) -> tuple[str, str, str]:
    subject = "OrgMFA: восстановление пароля"
    text = (
        f"Здравствуйте, {name or 'сотрудник'}!\n"
        f"Кто-то запросил сброс пароля для учётной записи, привязанной к этому адресу.\n"
        f"Ссылка для смены пароля (действует {ttl_min} минут, одноразовая):\n{link}\n\n"
        f"Если вы не запрашивали сброс — ничего не делайте: пароль останется прежним,\n"
        f"но рекомендуем сменить его и проверить журнал входов в личном кабинете."
    )
    return subject, text, _wrap(text.replace("\n", "<br>"))


def mail_failed_attempts(to: str, name: str, attempts: int, ip: str, lock_note: str) -> tuple[str, str, str]:
    subject = "OrgMFA: серия неудачных попыток входа"
    text = (
        f"Здравствуйте, {name or 'сотрудник'}!\n"
        f"Зафиксировано {attempts} неудачных попыток входа в вашей учётной записи\n"
        f"с адреса {ip}. {lock_note}\n\n"
        f"Что сделать:\n"
        f"1. Если это были не вы — немедленно смените пароль (ссылка «Забыли пароль?»\n"
        f"   на странице входа) и перевыпустите резервные коды в личном кабинете.\n"
        f"2. Проверьте журнал событий безопасности в личном кабинете.\n"
        f"3. Сообщите администратору ИС, если атаки повторяются."
    )
    return subject, text, _wrap(text.replace("\n", "<br>"))
