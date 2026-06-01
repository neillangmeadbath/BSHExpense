import datetime as dt
import os
import re
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

import pyotp
from flask import Flask, g, jsonify, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

EMAIL_PATTERN = re.compile(r"^[a-z]+\.[a-z]+@bsh-infraconsult\.com$")
CURRENCY_SYMBOLS = {"€": "EUR", "$": "USD", "£": "GBP"}


def create_app(test_config: Optional[dict] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret"),
        DATABASE=os.environ.get("DATABASE", str(Path(app.root_path) / "expenses.db")),
        TOKEN_MAX_AGE=60 * 60 * 12,
    )
    if test_config:
        app.config.update(test_config)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db() -> None:
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT
            );

            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                merchant TEXT NOT NULL,
                expense_date TEXT NOT NULL,
                description TEXT,
                original_amount REAL NOT NULL,
                original_currency TEXT NOT NULL,
                amount_eur REAL NOT NULL,
                receipt_filename TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            """
        )
        db.commit()

    with app.app_context():
        init_db()

    def serializer() -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(app.config["SECRET_KEY"])

    def make_token(user_id: int) -> str:
        return serializer().dumps({"user_id": user_id})

    def parse_token(token: str) -> Optional[int]:
        try:
            data = serializer().loads(token, max_age=app.config["TOKEN_MAX_AGE"])
            return int(data["user_id"])
        except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError):
            return None

    def require_auth(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "missing bearer token"}), 401
            user_id = parse_token(auth_header.split(" ", 1)[1].strip())
            if not user_id:
                return jsonify({"error": "invalid token"}), 401
            g.user_id = user_id
            return fn(*args, **kwargs)

        return wrapper

    def get_rate_to_eur(currency: str) -> float:
        currency = currency.upper()
        override = app.config.get("RATE_PROVIDER")
        if callable(override):
            return float(override(currency))

        if currency == "EUR":
            return 1.0

        from urllib.error import URLError
        from urllib.request import urlopen
        import json

        try:
            url = f"https://api.frankfurter.app/latest?from={currency}&to=EUR"
            with urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
                return float(data["rates"]["EUR"])
        except (URLError, KeyError, ValueError, TypeError):
            fallback = {"USD": 0.92, "GBP": 1.17}
            if currency in fallback:
                return fallback[currency]
            raise ValueError(f"unsupported currency or conversion failed for {currency}")

    def extract_receipt_data(filename: str, content: bytes) -> dict:
        extractor: Optional[Callable[[str, bytes], dict]] = app.config.get("RECEIPT_EXTRACTOR")
        if callable(extractor):
            return extractor(filename, content)

        text = content.decode("utf-8", errors="ignore")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        merchant = lines[0][:120] if lines else Path(filename).stem

        date_match = re.search(r"(20\d{2}-\d{2}-\d{2})", text)
        expense_date = date_match.group(1) if date_match else dt.date.today().isoformat()

        amount_match = re.search(r"(?i)(?:total|amount)\s*[:]?\s*([€$£]?\s*\d+(?:[\.,]\d{2})?)", text)
        amount_str = amount_match.group(1).replace(" ", "") if amount_match else "0"

        currency = "EUR"
        if amount_str and amount_str[0] in CURRENCY_SYMBOLS:
            currency = CURRENCY_SYMBOLS[amount_str[0]]
            amount_str = amount_str[1:]
        else:
            code_match = re.search(r"\b(EUR|USD|GBP)\b", text, re.IGNORECASE)
            if code_match:
                currency = code_match.group(1).upper()

        amount = float(amount_str.replace(",", "."))

        description = lines[1][:250] if len(lines) > 1 else "Receipt import"
        return {
            "merchant": merchant,
            "expense_date": expense_date,
            "description": description,
            "amount": amount,
            "currency": currency,
        }

    def save_expense(user_id: int, payload: dict, receipt_filename: Optional[str] = None) -> dict:
        amount = float(payload["amount"])
        currency = payload.get("currency", "EUR").upper()
        rate = get_rate_to_eur(currency)
        amount_eur = round(amount * rate, 2)

        db = get_db()
        db.execute(
            """
            INSERT INTO expenses (
                user_id, merchant, expense_date, description,
                original_amount, original_currency, amount_eur,
                receipt_filename, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                payload["merchant"],
                payload.get("expense_date", dt.date.today().isoformat()),
                payload.get("description", ""),
                amount,
                currency,
                amount_eur,
                receipt_filename,
                dt.datetime.now(dt.UTC).isoformat(),
            ),
        )
        db.commit()

        return {
            "merchant": payload["merchant"],
            "expense_date": payload.get("expense_date", dt.date.today().isoformat()),
            "description": payload.get("description", ""),
            "original_amount": amount,
            "original_currency": currency,
            "amount_eur": amount_eur,
            "receipt_filename": receipt_filename,
        }

    @app.post("/auth/signup")
    def signup():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).lower().strip()
        password = str(data.get("password", ""))

        if not EMAIL_PATTERN.fullmatch(email):
            return jsonify({"error": "only BSH Infraconsult email addresses are allowed"}), 400
        if len(password) < 8:
            return jsonify({"error": "password must be at least 8 characters"}), 400

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "email already registered"}), 409

        return jsonify({"message": "account created"}), 201

    @app.post("/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).lower().strip()
        password = str(data.get("password", ""))
        totp_code = str(data.get("totp_code", "")).strip()

        db = get_db()
        user = db.execute("SELECT id, password_hash, totp_secret FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "invalid credentials"}), 401

        if user["totp_secret"]:
            if not totp_code or not pyotp.TOTP(user["totp_secret"]).verify(totp_code, valid_window=1):
                return jsonify({"error": "2FA code required or invalid"}), 401

        return jsonify({"token": make_token(user["id"])}), 200

    @app.post("/auth/2fa/setup")
    @require_auth
    def setup_2fa():
        secret = pyotp.random_base32()
        db = get_db()
        db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, g.user_id))
        db.commit()

        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=str(g.user_id), issuer_name="BSHExpense"
        )
        return jsonify({"secret": secret, "provisioning_uri": provisioning_uri}), 200

    @app.get("/expenses")
    @require_auth
    def list_expenses():
        db = get_db()
        rows = db.execute(
            """
            SELECT id, merchant, expense_date, description, original_amount, original_currency,
                   amount_eur, receipt_filename, created_at
            FROM expenses
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (g.user_id,),
        ).fetchall()
        return jsonify([dict(row) for row in rows]), 200

    @app.post("/expenses")
    @require_auth
    def create_expense():
        data = request.get_json(silent=True) or {}
        if "merchant" not in data or "amount" not in data:
            return jsonify({"error": "merchant and amount are required"}), 400
        data.setdefault("currency", "EUR")
        try:
            saved = save_expense(g.user_id, data)
        except (ValueError, TypeError):
            return jsonify({"error": "invalid expense payload"}), 400
        return jsonify(saved), 201

    @app.post("/expenses/upload")
    @require_auth
    def upload_receipt():
        file = request.files.get("receipt")
        if file is None or not file.filename:
            return jsonify({"error": "receipt file is required"}), 400
        parsed = extract_receipt_data(file.filename, file.read())
        saved = save_expense(g.user_id, parsed, receipt_filename=file.filename)
        return jsonify(saved), 201

    @app.post("/expenses/batch-upload")
    @require_auth
    def batch_upload_receipts():
        files = request.files.getlist("receipts")
        if not files:
            return jsonify({"error": "at least one receipt is required"}), 400

        created = []
        for file in files:
            if not file.filename:
                continue
            parsed = extract_receipt_data(file.filename, file.read())
            created.append(save_expense(g.user_id, parsed, receipt_filename=file.filename))

        return jsonify(created), 201

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000)
