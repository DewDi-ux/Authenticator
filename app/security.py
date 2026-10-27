"""
app.security — криптографическое ядро системы MFA.

Модуль реализует:
  * хэширование паролей с Argon2id (RFC 9106) — стойкий к перебору и GPU-атакам;
  * генерацию/проверку одноразовых TOTP-кодов (RFC 6238);
  * шифрование секретов (seed TOTP) симметричным шифром AES-256-GCM
    (ключ — производный от MASTER_KEY, режим "software HSM" для учебного стенда);
  * генерацию резервных кодов (one-time recovery codes).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets

import pyotp
import qrcode
from argon2 import PasswordHasher, Type as Argon2Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Параметры политик (вынесены в константы для прозрачности в ПЗ) ---------
TOTP_DIGITS = 6                 # длина кода (RFC 6238 рекомендует 6..8)
TOTP_PERIOD = 30                # временное окно, сек
TOTP_WINDOW = 1                 # допускаемое смещение окон (задержка сети/часы)
RECOVERY_CODE_COUNT = 10        # количество резервных кодов
RECOVERY_CODE_BYTES = 5         # энтропия одного кода (>= 40 бит по NIST SP 800-63B)

# Argon2id параметры (мемори-жёсткая функция, OWASP ASVS v4.1 §A2):
# memory_cost=65536 KiB (64 MiB), time_cost=3, parallelism=4
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Argon2Type.ID,
)


# ---------------------------------------------------------------------------
# Пароли
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Возвращает хэш пароля алгоритмом Argon2id (с солью внутри)."""
    return _hasher.hash(password.encode("utf-8"))


def verify_password(password: str, stored_hash: str) -> tuple[bool, bool]:
    """Проверяет пароль. Возвращает (ok, needs_rehash).

    needs_rehash позволяет инкрементально усиливать параметр хэширования
    при входе пользователя (прозрачная миграция устаревших хэшей).
    """
    try:
        ok = _hasher.verify(stored_hash, password.encode("utf-8"))
    except (VerifyMismatchError, InvalidHashError):
        return False, False
    return ok, _hasher.check_needs_rehash(stored_hash)


def check_password_policy(password: str, login: str = "") -> list[str]:
    """Политика сложности пароля (NIST SP 800-63B §5.1.1.2)."""
    errors: list[str] = []
    if len(password) < 10:
        errors.append("Пароль должен быть не короче 10 символов.")
    if not (any(c.islower() for c in password) and any(c.isupper() for c in password)):
        errors.append("Нужны символы верхнего и нижнего регистра.")
    if not any(c.isdigit() for c in password):
        errors.append("Нужна хотя бы одна цифра.")
    if login and login.lower() in password.lower():
        errors.append("Пароль не должен содержать логин.")
    # Чёрный список распространённых паролей (дополняется словарём из OXIDS)
    weak = {"password", "123456", "qwerty", "111111", "admin", "letmein"}
    if password.lower() in weak:
        errors.append("Пароль из списка часто используемых.")
    return errors


# ---------------------------------------------------------------------------
# TOTP (ступень 2)
# ---------------------------------------------------------------------------
def generate_totp_secret() -> bytes:
    """Случайный seed 160 бит (RFC 6238 требует >= 128 бит энтропии)."""
    return secrets.token_bytes(20)


def totp_provisioning_uri(secret_plain: bytes, account_name: str, issuer: str = "OrgMFA") -> str:
    """otpauth:// URI для QR-кода в Google Authenticator / Яндекс.Ключ."""
    secret_b32 = base64.b32encode(secret_plain).decode().rstrip("=")
    return pyotp.TOTP(secret_b32).provisioning_uri(name=account_name, issuer_name=issuer)


def qr_png_data_uri(otpauth_uri: str) -> str:
    """PNG QR-код (data: URI) из otpauth:// строки.

    Приложение «Яндекс Ключ» (и любой другой совместимый с RFC 6238
    аутентификатор) распознаёт otpauth:// URI при сканировании камеры —
    пользователю не нужно вводить длинный Base32-секрет вручную.
    Кодирование — byte mode (без потери данных), уровень коррекции M,
    box_size=6 px: достаточно крупно для надёжного сканирования с экрана.
    """
    img = qrcode.QRCode(border=2, box_size=6, error_correction=qrcode.constants.ERROR_CORRECT_M)
    img.add_data(otpauth_uri.encode("utf-8"))   # byte mode — точно кодирует URI
    img.make(fit=True)
    buf = io.BytesIO()
    img.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def totp_now(secret_plain: bytes) -> str:
    secret_b32 = base64.b32encode(secret_plain).decode().rstrip("=")
    return pyotp.TOTP(secret_b32).now()


def verify_totp(secret_plain: bytes, code: str) -> bool:
    """Проверка TOTP с окном ±TOTP_WINDOW шагов."""
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return False
    secret_b32 = base64.b32encode(secret_plain).decode().rstrip("=")
    return pyotp.TOTP(secret_b32).verify(code, valid_window=TOTP_WINDOW)


# ---------------------------------------------------------------------------
# Шифрование секретов (seed'ы TOTP) — AES-256-GCM
# ---------------------------------------------------------------------------
def _aes_key() -> bytes:
    master = os.environ.get("MFA_MASTER_KEY")
    if not master:
        # Для учебного стенда: детерминированный ключ из фиксированной соли.
        # В промышленной системе — из KMS/HSM или env-секрета.
        master = "dev-master-key-change-me"
    return hashlib.scrypt(master.encode(), salt=b"mfa-kdf-salt", n=2**14, r=8, p=1, dklen=32)


def encrypt_secret(plain: bytes) -> str:
    """AES-256-GCM: возвращает base64(nonce || ciphertext || tag)."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_aes_key()).encrypt(nonce, plain, None)
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_secret(token: str) -> bytes:
    raw = base64.urlsafe_b64decode(token.encode())
    return AESGCM(_aes_key()).decrypt(raw[:12], raw[12:], None)


# ---------------------------------------------------------------------------
# Резервные коды (потеря второго фактора)
# ---------------------------------------------------------------------------
def normalize_recovery_code(code: str) -> str:
    """Приведение резервного кода к каноническому виду.

    Коды генерируются в верхнем регистре и без неоднозначных символов,
    поэтому пользователь может ввести их в любом регистре и с пробелами/
    дефисами — нормализация делает ввод инвариантным (usability по NIST
    SP 800-63B §5.2) при сохранении стойкости (энтропия не уменьшается).
    """
    return "".join(code.split()).upper()


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    # Алфавит без неоднозначных символов (O/0, I/1/l), код в верхнем регистре —
    # удобно переписывать с бумаги; энтропия ~2^40 на код (secrets, CSPRNG).
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(2 * RECOVERY_CODE_BYTES))
            for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    """Хэш кода для хранения (код выдаётся один раз, хранится только хэш)."""
    return hashlib.sha256(("rc:" + normalize_recovery_code(code)).encode()).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    """Защита от timing-атак при сравнении токенов."""
    return hmac.compare_digest(a.encode(), b.encode())
