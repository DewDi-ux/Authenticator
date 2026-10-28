"""
app.mailer — отправка писем пользователю (восстановление пароля,
уведомления о подозрительной активности).

Транспорт: Gmail SMTP (или любой другой SMTP-сервер) через STARTTLS.
Все секреты берутся ТОЛЬКО из переменных окружения (файл .env не коммитится):

    SMTP_USER      ящик отправителя, например you@gmail.com  (обязательно)
    SMTP_PASS      App Password Gmail — 16 символов БЕЗ пробелов (обязательно)
                   (Google Account → Security → 2-Step Verification →
                    App passwords; обычный пароль аккаунта НЕ подойдёт)
    SMTP_HOST      по умолчанию smtp.gmail.com
    SMTP_PORT      по умолчанию 587 (STARTTLS); для 465 поставьте SMTP_SSL=1
    SMTP_SSL       1 — использовать implicit TLS (порт 465), иначе STARTTLS
    MAIL_FROM      адрес/имя в поле "From" (по умолчанию = SMTP_USER)

Если SMTP_USER или SMTP_PASS не заданы, включается режим стенда "console":
письмо не уходит в сеть, а записывается в журнал аудита и печатается в консоль.
Для локальных прогонов pytest это безопасный вариант по умолчанию.

Письма отправляются ФОНОВЫМ ЗАДАЧЕМ FastAPI (starlette BackgroundTasks),
чтобы сетевая задержка не блокировала ответ аутентификации; ошибка доставки
фиксируется в журнале аудита и НЕ влияет на результат входа.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

try:  # необязательная зависимость: если есть — подхватим .env автоматически
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover - стенд работает и без python-dotenv
    pass

from . import store

TIMEOUT_SEC = 15


def is_configured() -> bool:
    """True, если заданы учётные данные SMTP (реальная доставка)."""
    return bool(os.environ.get("SMTP_USER") and os.environ.get("SMTP_PASS"))


def sender() -> str:
    """Адрес отправителя из MAIL_FROM (по умолчанию — SMTP_USER)."""
    return os.environ.get("MAIL_FROM") or os.environ.get("SMTP_USER", "")


def send_email(to: str, subject: str, text_body: str,
               html_body: str | None = None) -> bool:
    """Отправка одного письма. Возвращает True при успехе.

    Никогда не бросает исключение наружу — вызывающий код (обработчик входа)
    не должен падать из-за проблем почты.
    """
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")

    if not user or not password:
        # стендовый режим: без внешнего трафика, факт — в аудит
        store.audit("mail.console", actor=to, success=True,
                    details={"subject": subject})
        print(f"[mailer:console] to={to} subject={subject!r}")
        return True

    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    use_ssl = os.environ.get("SMTP_SSL", "0") == "1"
    port = int(os.environ.get("SMTP_PORT", "465" if use_ssl else "587"))
    from_addr = sender() or user

    msg = _build_message(from_addr, to, subject, text_body, html_body)

    try:
        context = ssl.create_default_context()
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=TIMEOUT_SEC,
                                  context=context) as server:
                server.login(user, password)
                server.sendmail(from_addr, [to], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=TIMEOUT_SEC) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(user, password)
                server.sendmail(from_addr, [to], msg.as_string())
        store.audit("mail.sent", actor=to, success=True,
                    details={"subject": subject})
        return True
    except Exception as e:  # noqa: BLE001 — почта не должна ронять вход
        store.audit("mail.failed", actor=to, success=False,
                    details={"subject": subject, "error": str(e)[:200]})
        return False


def _build_message(from_addr: str, to: str, subject: str,
                   text_body: str, html_body: str | None) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = formataddr((str(Header("OrgMFA", "utf-8")), from_addr))
    msg["To"] = to
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="orgmfa.local")
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    if html_body:
        msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg


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
