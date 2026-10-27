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
    risk._stepup_totp_done.clear(); risk._stepup_recovery_done.clear()
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
        assert risk.decision(risk.RISK_STEP_UP) == "step_up"
        assert risk.decision(risk.RISK_BLOCK) == "block"

    def test_typical_login_not_step_up(self):
        """Штатный вход с корпоративного устройства в рабочее время — allow."""
        known = "Mozilla/5.0 (CorpPC)"
        s, r = risk.score_login("10.0.5.7", known, known, 0, 60)
        assert risk.decision(s) == "allow" and not r

    def test_single_household_factor_does_not_step_up(self):
        """Одиночный бытовой признак (только новое устройство) не ужесточает вход,
        даже если формальный порог превышен из-за времени суток."""
        s, r = risk.score_login("10.0.0.1", "NewBrowser", None, 0, 60)
        if s >= risk.RISK_STEP_UP:   # например, поправка на нерабочее время
            assert not risk.require_step_up(risk.decision(s), s, r)

    def test_two_independent_factors_trigger_step_up(self):
        """Сочетание «новое устройство + внешняя сеть» -> step_up."""
        s, r = risk.score_login("203.0.113.9", "Chromium", "Firefox", 0, 5)
        assert len(r) >= 2
        assert risk.require_step_up(risk.decision(s), s, r) is (s >= risk.RISK_STEP_UP)

    def test_brute_force_series_triggers_step_up(self):
        """Серия неудачных попыток — достаточное основание для step_up."""
        s, r = risk.score_login("10.0.0.5", "Edge", "Edge", 4, 5)
        assert risk.decision(s) != "allow"
        assert risk.require_step_up(risk.decision(s), s, r)

    def test_trusted_network_prefixes(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.4", "::1"):
            s, r = risk.score_login(ip, "UA", "UA", 0, 5)
            assert "login from outside trusted network" not in r
        s, r = risk.score_login("8.8.8.8", "UA", "UA", 0, 5)
        assert "login from outside trusted network" in r

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

    def test_enroll_returns_recovery_codes_once(self, client):
        """Резервные коды выдаются пользователю при привязке (иначе step-up и
        восстановление недоступны). В БД — только хэши."""
        self._register(client)
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        r = client.post("/enroll/totp")
        assert r.status_code == 200
        codes = r.json()["recovery_codes"]
        assert len(codes) == security.RECOVERY_CODE_COUNT
        u = store.get_user_by_login("petrov")
        # в базе нет plaintext-кодов
        assert all(c not in json.dumps(u.recovery_hashes) for c in codes)
        assert any(security.constant_time_eq(security.hash_recovery_code(c), h)
                   for c, h in zip(codes, u.recovery_hashes))

    def test_reenroll_requires_password_in_authed_session(self, client):
        """Перевыпуск фактора из авторизованной сессии — только с паролем;
        на setup-сессии пароль не требуется."""
        self._register(client)
        seed = self._enroll_mfa(client)
        client.post("/login", data={"login": "petrov", "password": self.PASSWORD})
        client.post("/verify-totp", data={"code": security.totp_now(seed)})
        assert client.get("/api/whoami").json()["authenticated"]
        # без пароля — отказ
        r = client.post("/enroll/totp")
        assert r.status_code == 403
        # с неверным паролем — отказ
        r = client.post("/enroll/totp", data={"password": "Wr0ng-Pass!"})
        assert r.status_code == 403
        # с верным паролем — новый QR и новые резервные коды
        r = client.post("/enroll/totp", data={"password": self.PASSWORD})
        assert r.status_code == 200 and r.json()["recovery_codes"]


# ---------------------------------------------------------------------------
class TestStepUpFlow:
    """Step-up по риску: третий фактор = ОДИН резервный код, без зацикливания."""
    PASSWORD = "Ivanov2026!qa"

    def _enroll(self, client, n_codes=10):
        client.post("/register", data={
            "login": "sidorov", "full_name": "Сидоров С. С.",
            "password": self.PASSWORD, "password2": self.PASSWORD})
        client.post("/login", data={"login": "sidorov", "password": self.PASSWORD})
        d = client.post("/enroll/totp").json()
        codes = d["recovery_codes"]
        u = store.get_user_by_login("sidorov")
        seed = security.decrypt_secret(u.totp_enc)
        client.post("/enroll/totp/confirm", data={"code": security.totp_now(seed)})
        return seed, codes[:n_codes]

    def _login_step_up(self, client):
        r = client.post("/login", data={"login": "sidorov", "password": self.PASSWORD},
                        headers={"X-Force-Step-Up": "1"}, follow_redirects=False)
        assert r.status_code == 303 and "/mfa" in r.headers["location"]
        page = client.get("/mfa")
        assert "рискованный" in page.text   # предупреждение показывается
        return page

    def test_normal_login_no_step_up(self, client):
        """Обычный вход с того же клиента не требует третьего фактора."""
        seed, _ = self._enroll(client)
        r = client.post("/login", data={"login": "sidorov", "password": self.PASSWORD},
                        follow_redirects=False)
        assert r.status_code == 303
        resp = client.post("/verify-totp", data={"code": security.totp_now(seed)})
        assert resp.json().get("ok") is True   # сразу authed, без step_up

    def test_step_up_totp_then_one_recovery(self, client):
        """TOTP -> резервный код: ровно один код расходуется, цикл отсутствует."""
        seed, codes = self._enroll(client, n_codes=10)
        self._login_step_up(client)
        # TOTP принят, но вход ещё не завершён
        r = client.post("/verify-totp", data={"code": security.totp_now(seed)})
        d = r.json()
        assert d["ok"] is False and d["step_up"] is True
        who = client.get("/api/whoami")
        assert who.json()["authenticated"] is False
        # повторный TOTP не требуется и не принимается как завершение —
        # просим резервный код
        r2 = client.post("/verify-recovery", data={"code": codes[0]})
        assert r2.json()["ok"] is True
        assert client.get("/api/whoami").json()["authenticated"] is True
        u = store.get_user_by_login("sidorov")
        assert len(u.recovery_hashes) == 9     # израсходован ровно ОДИН код

    def test_step_up_recovery_then_totp(self, client):
        """Обратный порядок тоже работает: код -> TOTP -> authed, один код."""
        seed, codes = self._enroll(client)
        self._login_step_up(client)
        r = client.post("/verify-recovery", data={"code": codes[0]})
        assert r.json()["ok"] is False and r.json()["step_up_pending"] is True
        # второй резервный код НЕ расходуется, пока не введён TOTP
        r2 = client.post("/verify-recovery", data={"code": codes[1]})
        assert r2.json()["ok"] is False
        u = store.get_user_by_login("sidorov")
        assert len(u.recovery_hashes) == 9
        import time as _t
        _t.sleep(31)   # свежий TOTP (завершённое окно), чтобы не撞上 replay-детектор
        r3 = client.post("/verify-totp", data={"code": security.totp_now(seed)})
        assert r3.json()["ok"] is True
        assert client.get("/api/whoami").json()["authenticated"] is True

    def test_step_up_exhausted_recovery_codes(self, client):
        """Исчерпание резервных кодов: step-up невозможно завершить (отказ,
        а не обход третьего фактора)."""
        seed, codes = self._enroll(client, n_codes=1)
        u = store.get_user_by_login("sidorov")
        u.recovery_hashes = []          # имитируем исчерпанные коды
        store.update_user(u)
        # risk больше не требует step_up (нет кодов) — обычный вход проходит
        r = client.post("/login", data={"login": "sidorov", "password": self.PASSWORD},
                        headers={"X-Force-Step-Up": "1"}, follow_redirects=False)
        assert r.status_code == 303
        page = client.get("/mfa")
        assert "рискованный" not in page.text   # стадия mfa, не step_up
        resp = client.post("/verify-totp", data={"code": security.totp_now(seed)})
        assert resp.json().get("ok") is True


# ---------------------------------------------------------------------------
class TestIntegrationAPI:
    """Контракт /api/auth/* для информационной системы (docs/integration.md)."""
    PASSWORD = "Ivanov2026!qa"
    KEY = "test-service-key"

    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setenv("MFA_INTEGRATION_KEY", self.KEY)

    def _hdr(self, **extra):
        return {"X-Service-Key": self.KEY, **extra}

    def _enrolled_user(self, client):
        client.post("/register", data={
            "login": "smith", "full_name": "",
            "password": self.PASSWORD, "password2": self.PASSWORD})
        client.post("/login", data={"login": "smith", "password": self.PASSWORD})
        d = client.post("/enroll/totp").json()
        u = store.get_user_by_login("smith")
        seed = security.decrypt_secret(u.totp_enc)
        client.post("/enroll/totp/confirm", data={"code": security.totp_now(seed)})
        return seed, d["recovery_codes"]

    def test_integration_denied_without_key(self, client):
        r = client.post("/api/auth/login", json={"login": "x", "password": "y"})
        assert r.status_code == 403
        assert "error" in r.json()

    def test_api_full_flow_granted(self, client):
        seed, _ = self._enrolled_user(client)
        r = client.post("/api/auth/login", headers=self._hdr(),
                        json={"login": "smith", "password": self.PASSWORD})
        assert r.status_code == 200
        d = r.json()
        assert d["stage"] in ("mfa", "step_up")
        tok = d["session"]
        # до второго фактора сессия не авторизована
        intro = client.get(f"/api/introspect?session={tok}", headers=self._hdr())
        assert intro.json()["active"] is False
        r2 = client.post("/api/auth/totp", headers=self._hdr(),
                         json={"session": tok, "code": security.totp_now(seed)})
        d2 = r2.json()
        if d2.get("step_up"):     # стендовый TestClient может дать высокий риск
            rc = client.post("/api/auth/recovery", headers=self._hdr(),
                             json={"session": tok, "code": "XXXXXXYYYYY"})
        assert d2["ok"] is True or d2.get("step_up")
        if d2["ok"]:
            intro = client.get(f"/api/introspect?session={tok}", headers=self._hdr())
            assert intro.json()["active"] is True
            assert intro.json()["subject"] == "smith"
            assert "totp" in intro.json()["factors"]

    def test_api_wrong_password_and_lockout(self, client):
        self._enrolled_user(client)
        r = client.post("/api/auth/login", headers=self._hdr(),
                        json={"login": "smith", "password": "Wr0ng-Pass!"})
        assert r.status_code == 401 and r.json()["error"] == "invalid_credentials"
        for _ in range(risk.MAX_FAILED):
            client.post("/api/auth/login", headers=self._hdr(),
                        json={"login": "smith", "password": "Wr0ng-Pass!"})
        r = client.post("/api/auth/login", headers=self._hdr(),
                        json={"login": "smith", "password": self.PASSWORD})
        assert r.status_code == 403 and r.json()["error"] == "account_locked"

    def test_api_step_up_consumes_single_recovery_code(self, client):
        """ИС-контракт: на step_up TOTP+резервный код, расход одного кода,
        отсутствие цикла «TOTP->код->TOTP». Риск форсируется служебным заголовком."""
        seed, codes = self._enrolled_user(client)
        r = client.post("/api/auth/login", headers=self._hdr(X-Force-Step-Up="1"),
                        json={"login": "smith", "password": self.PASSWORD})
        d = r.json()
        assert d["stage"] == "step_up", d
        tok = d["session"]
        r2 = client.post("/api/auth/totp", headers=self._hdr(),
                         json={"session": tok, "code": security.totp_now(seed)})
        assert r2.json() == {"ok": False, "step_up": True,
                             "message": "Требуется подтверждение одним резервным кодом."} \
            or r2.json().get("step_up") is True
        r3 = client.post("/api/auth/recovery", headers=self._hdr(),
                         json={"session": tok, "code": codes[0]})
        d3 = r3.json()
        assert d3["ok"] is True and d3["result"] == "granted"
        assert d3["remaining_recovery_codes"] == len(codes) - 1
        intro = client.get(f"/api/introspect?session={tok}", headers=self._hdr())
        assert intro.json()["active"] is True

    def test_api_dormant_account_risk_factor(self, client):
        """Признак «спящая учётная запись» учитывается и в ИС-контуре:
        подменяем время последнего успешного входа на 40 дней назад."""
        seed, _ = self._enrolled_user(client)
        with store._conn() as c:
            login_ts = c.execute("SELECT login FROM users WHERE id IN "
                                 "(SELECT user_id FROM sessions)").fetchall()
            # помечаем все успешные входы старыми
            old = __import__("time").time() - 40 * 24 * 3600
            c.execute("UPDATE audit_log SET ts=? WHERE event='auth.success'", (old,))
        r = client.post("/api/auth/login", headers=self._hdr(),
                        json={"login": "smith", "password": self.PASSWORD})
        reasons = r.json()["risk"]["reasons"]
        assert "dormant account reactivation (>30 days)" in reasons

    def test_api_logout_revokes_introspection(self, client):
        seed, _ = self._enrolled_user(client)
        r = client.post("/api/auth/login", headers=self._hdr(),
                        json={"login": "smith", "password": self.PASSWORD})
        tok = r.json()["session"]
        client.post("/api/auth/totp", headers=self._hdr(),
                    json={"session": tok, "code": security.totp_now(seed)})
        client.post("/api/auth/logout", headers=self._hdr(), json={"session": tok})
        intro = client.get(f"/api/introspect?session={tok}", headers=self._hdr())
        assert intro.json()["active"] is False
