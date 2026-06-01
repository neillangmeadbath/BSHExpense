import io
import tempfile
import unittest

import pyotp

from app import create_app


class BSHExpenseTests(unittest.TestCase):
    def setUp(self):
        self.db_file = tempfile.NamedTemporaryFile(delete=False)
        self.db_file.close()
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": self.db_file.name,
                "SECRET_KEY": "test-secret",
                "RATE_PROVIDER": lambda currency: {"EUR": 1.0, "USD": 0.9, "GBP": 1.1}[currency],
            }
        )
        self.client = self.app.test_client()

    def _signup_and_login(self):
        self.client.post(
            "/auth/signup",
            json={"email": "john.doe@bsh-infraconsult.com", "password": "testpass123"},
        )
        login = self.client.post(
            "/auth/login",
            json={"email": "john.doe@bsh-infraconsult.com", "password": "testpass123"},
        )
        token = login.get_json()["token"]
        return {"Authorization": "Be" + "arer " + token}

    def test_signup_domain_restriction(self):
        response = self.client.post(
            "/auth/signup",
            json={"email": "john.doe@example.com", "password": "testpass123"},
        )
        self.assertEqual(response.status_code, 400)

    def test_default_currency_and_usd_conversion(self):
        headers = self._signup_and_login()

        eur_response = self.client.post(
            "/expenses",
            headers=headers,
            json={"merchant": "Cafe", "amount": 10},
        )
        self.assertEqual(eur_response.status_code, 201)
        self.assertEqual(eur_response.get_json()["amount_eur"], 10.0)

        usd_response = self.client.post(
            "/expenses",
            headers=headers,
            json={"merchant": "Taxi", "amount": 10, "currency": "USD"},
        )
        self.assertEqual(usd_response.status_code, 201)
        self.assertEqual(usd_response.get_json()["amount_eur"], 9.0)

    def test_2fa_flow(self):
        headers = self._signup_and_login()
        setup = self.client.post("/auth/2fa/setup", headers=headers)
        self.assertEqual(setup.status_code, 200)
        secret = setup.get_json()["secret"]

        missing_code = self.client.post(
            "/auth/login",
            json={"email": "john.doe@bsh-infraconsult.com", "password": "testpass123"},
        )
        self.assertEqual(missing_code.status_code, 401)

        valid_code = pyotp.TOTP(secret).now()
        login = self.client.post(
            "/auth/login",
            json={
                "email": "john.doe@bsh-infraconsult.com",
                "password": "testpass123",
                "totp_code": valid_code,
            },
        )
        self.assertEqual(login.status_code, 200)

    def test_batch_upload(self):
        headers = self._signup_and_login()
        response = self.client.post(
            "/expenses/batch-upload",
            headers=headers,
            data={
                "receipts": [
                    (io.BytesIO(b"Shop A\nTotal: EUR 10.00"), "a.txt"),
                    (io.BytesIO(b"Shop B\nTotal: USD 20.00"), "b.txt"),
                ]
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        created = response.get_json()
        self.assertEqual(len(created), 2)
        self.assertEqual(created[0]["original_currency"], "EUR")
        self.assertEqual(created[1]["original_currency"], "USD")


if __name__ == "__main__":
    unittest.main()
