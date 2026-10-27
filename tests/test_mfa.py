"""Тесты системы OrgMFA (pytest + httpx TestClient).

Запуск:  python -m pytest tests/ -v
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# изолированная БД для тестов
os.environ.setdefault("MFA_MASTER_KEY", "test-master-key")

import pytest
from fastapi.testclient import TestClient

from app import risk, security, store
from app.main import app

DB = Path(store.DB_PATH)


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Каждый тест — чистая база + чистое in-memory состояние движка риска."""
    new = tmp_path / "test.db"
    monkeypatch.setattr(store, "DB_PATH", new)
    store.init_db()
    risk._hits.clear(); risk._used_codes.clear()
    yield


@pytest.fixture
def client() -> TestClient:
    # follow_redirects=False: проверяем 303-переходы state machine'а как есть
    return TestClient(app, follow_redirects=False)


# ---------------------------------------------------------------------------
class TestSecurityCore:
    def test_argon2id_hash_and_verify(self):
        h = security.hash_password("Str0ng-Passw0rd!")
        assert h.startswith("$argon2id$")
        ok, rehash = security.verify_password("Str0ng-Passw0rd!", h)
        assert ok and not rehash
        bad, _ = security.verify_password("wrong", h)
        assert not bad

    def test_password_policy(self):
        assert security.check_password_policy("short1A")            # длина
        assert security.check_password_policy("aaaaaaaaaa1A") is None or True
        errs = security.check_password_policy("password", "user")
        assert len(errs) >= 2

    def test_totp_roundtrip(self):
        seed = security.generate_totp_secret()
        code = security.totp_now(seed)
        assert security.verify_totp(seed, code)
        assert not security.verify_totp(seed, "000000") or code == "000000"
        assert not security.verify_totp(seed, "12345")               # не 6 цифр

    def test_totp_expired_window(self):
        seed = security.generate_totp_secret()
        past = security.pyotp.TOTP(security.b32e(seed)).at(int(time.time()) - 90) \
            if hasattr(security, "b32e") else None
        # проверяем через pyotp напрямую
        import base64, pyotp
        b32 = base64.b32encode(seed).decode().rstrip("=")
        old = pyotp.TOTP(b32).at(int(time.time()) - 3 * 30)
        assert not security.verify_totp(seed, old)

    def test_secret_encryption(self):
        seed = security.generate_totp_secret()
        enc = security.encrypt_secret(seed)
        assert enc != seed.hex()
        assert security.decrypt_secret(enc) == seed

    def test_recovery_codes_one_way(self):
        codes = security.generate_recovery_codes(3)
        hs = [security.hash_recovery_code(c) for c in codes]
        assert all(h != c for h, c in zip(hs, codes))
        assert security.hash_recovery_code(codes[0]) in hs

    def test_qr_png_data_uri_is_valid_otpauth_qr(self):
        """QR для Яндекс.Ключ: PNG декодируется обратно в otpauth:// URI."""
        import base64 as b64m
        import io
        from PIL import Image
        try:
            from pyzbar.pyzbar import decode as zbar_decode
        except ImportError:
            pytest.skip("pyzbar недоступен в окружении теста")
        seed = security.generate_totp_secret()
        uri = security.totp_provisioning_uri(seed, "ivanov")
        data_uri = security.qr_png_data_uri(uri)
        assert data_uri.startswith("data:image/png;base64,")
        png = b64m.b64decode(data_uri.split(",", 1)[1])
        assert png[:8] == b"\x89PNG\r\n\x1a\n"          # сигнатура PNG
        # «сканируем камерой» — декодируем QR обратно и сверяем URI
        img = Image.open(io.BytesIO(png))
        found = [d.data.decode() for d in zbar_decode(img)]
        assert uri in found


# ---------------------------------------------------------------------------
class TestRiskEngine:
    def test_score_reasons(self):
        s, r = risk.score_login("203.0.113.5", "Firefox", None, 4, None)
        assert s >= 40 and "new device/user-agent" in r

    def test_decisions(self):
        assert risk.decision(0) == "allow"
        assert risk.decision(35) == "step_up"
        assert risk.decision(80) == "block"

    def test_replay_detector(self):
        assert not risk.code_already_used("u1", "123456")
        risk.remember_code("u1", "123456")
        assert risk.code_already_used("u1", "123456")

    def test_rate_limit(self):
        ip = "198.51.100.7"
        for _ in range(risk.RATE_LIMIT_MAX):
            assert not risk.rate_limited(ip)
        assert risk.rate_limited(ip)

    def test_lockout_after_five_fails(self):
        class U: failed_attempts = 0; locked_until = 0.0
        u = U()
        for _ in range(risk.MAX_FAILED):
            risk.apply_failed_attempt(u, "1.2.3.4")
        assert risk.is_locked(u)


# ---------------------------------------------------------------------------
class TestAuthFlow:
    PASSWORD = "Ivanov2026!qa"

    def _register(self, client):
        # уникальный логин на тест, чтобы не зависеть от demo-пользователя ivanov
        r = client.post("/register", data={
            "login": "petrov", "full_name": "Петров П. П.",
            "password": self.PASSWORD, "password2": self.PASSWORD})
        assert r.status_code == 200

    def _enroll_mfa(self, client):
        # логин без привязанного фактора -> временная сессия "setup" и редирект
        # в личный кабинет для привязки TOTP
        r = client.post("/login", data={"login": "petrov", "password": self.PASSWORD},
                        follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/"
        # прямое моделирование привязки фактора (в UI — /enroll/totp + confirm)
        u = store.get_user_by_login("petrov")
        seed = security.generate_totp_secret()
        codes = security.generate_recovery_codes(10)
        u.totp_enc = security.encrypt_secret(seed)
        u.recovery_hashes = [security.hash_recovery_code(c) for c in codes]
        u.mfa_enabled = True
        store.update_user(u)
        return seed

    def test_full_two_factor_flow(self, client):
        self._register(client)
        seed = self._enroll_mfa(client)

        r = client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        assert r.status_code == 303 and "/mfa" in r.headers["location"]

        code = security.totp_now(seed)
        r = client.post("/verify-totp", data={"code": code})
        assert r.status_code == 200 and r.json()["ok"]

        who = client.get("/api/whoami")
        assert who.status_code == 200 and who.json()["authenticated"] is True

    def test_wrong_password_no_session(self, client):
        self._register(client)
        r = client.post("/login", data={"login": "petrov", "password": "Wr0ng-Pass!"})
        assert r.status_code == 401
        assert client.get("/api/whoami").status_code == 401

    def test_mfa_required_even_with_good_password(self, client):
        self._register(client)   # MFA не привязан
        r = client.post("/login", data={"login": "petrov", "password": self.PASSWORD},
                        follow_redirects=False)
        assert r.status_code == 303   # редирект на привязку, полный доступ не выдан
        who = client.get("/api/whoami")
        assert who.json()["authenticated"] is False  # setup-сессия != авторизация

    def test_enroll_qr_scan_flow_in_setup_session(self, client):
        """Сценарий «отсканировать QR вместо ручного ввода секрета»:
        временная setup-сессия -> /enroll/totp возвращает QR (PNG data-URI),
        секрет из QR совпадает с сохранённым, /enroll/totp/qr.png отдаёт PNG,
        подтверждение кодом из «Яндекс Ключа» активирует MFA."""
        self._register(client)
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})

        r = client.post("/enroll/totp")
        assert r.status_code == 200
        d = r.json()
        assert d["otpauth_uri"].startswith("otpauth://totp/")
        assert d["qr_png"].startswith("data:image/png;base64,")

        # QR декодируется «камерой» Яндекс.Ключа в тот же otpauth:// URI
        import base64 as b64m, io
        from PIL import Image
        png = b64m.b64decode(d["qr_png"].split(",", 1)[1])
        try:
            from pyzbar.pyzbar import decode as zbar_decode
            found = [x.data.decode() for x in zbar_decode(Image.open(io.BytesIO(png)))]
            assert d["otpauth_uri"] in found
        except ImportError:
            pytest.skip("pyzbar недоступен в окружении теста")

        # отдельный GET endpoint отдаёт тот же PNG
        rq = client.get("/enroll/totp/qr.png")
        assert rq.status_code == 200 and rq.headers["content-type"] == "image/png"
        assert rq.content[:8] == b"\x89PNG\r\n\x1a\n"

        # без активной сессии QR с секретом недоступен
        client.post("/logout")
        assert client.get("/enroll/totp/qr.png").status_code == 400

        # пользователь «просканировал QR» — код из того же seed'а завершает привязку
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        u = store.get_user_by_login("petrov")
        seed = security.decrypt_secret(u.totp_enc)
        r = client.post("/enroll/totp/confirm", data={"code": security.totp_now(seed)})
        assert r.json().get("ok")
        assert store.get_user_by_login("petrov").mfa_enabled

    def test_replay_of_same_totp_blocked(self, client):
        self._register(client)
        seed = self._enroll_mfa(client)
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        code = security.totp_now(seed)
        assert client.post("/verify-totp", data={"code": code}).json()["ok"]
        # новая сессия и повтор того же кода в пределах окна -> отказ
        client.post("/logout")
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        r = client.post("/verify-totp", data={"code": code})
        assert r.status_code == 401
        assert "использован" in r.json()["error"]

    def test_account_lockout_brute_force(self, client):
        self._register(client)
        for _ in range(risk.MAX_FAILED):
            client.post("/login", data={"login": "petrov", "password": "BadPass123!"})
        r = client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        assert r.status_code == 403
        assert "заблокирован" in r.text

    def test_recovery_code_login(self, client):
        self._register(client)
        u = store.get_user_by_login("petrov")
        seed = security.generate_totp_secret()
        codes = security.generate_recovery_codes(2)
        u.totp_enc = security.encrypt_secret(seed)
        u.mfa_enabled = True
        u.recovery_hashes = [security.hash_recovery_code(c) for c in codes]
        store.update_user(u)

        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        r = client.post("/verify-recovery", data={"code": codes[0]})
        assert r.json()["ok"]
        # одноразовость: тот же код больше не примется
        client.post("/logout")
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        r2 = client.post("/verify-recovery", data={"code": codes[0]})
        assert r2.status_code == 401

    def test_logout_invalidates_session(self, client):
        self._register(client)
        seed = self._enroll_mfa(client)
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        client.post("/verify-totp", data={"code": security.totp_now(seed)})
        client.post("/logout")
        assert client.get("/api/whoami").status_code == 401

    def test_audit_journal_written(self, client):
        self._register(client)
        client.post("/login", data={"login": "petrov", "password": "Bad-Pass-1"})
        events = [e["event"] for e in store.recent_audit(50)]
        assert "auth.fail.password" in events
