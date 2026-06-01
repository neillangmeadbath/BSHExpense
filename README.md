# BSHExpense

Expense scanning and management for BSH Infraconsult GmbH employees.

## What is implemented

- Flask backend with SQLite expenses database
- Restricted sign-up (`first.last@bsh-infraconsult.com` only)
- Password login + optional TOTP 2FA
- Expense APIs with default EUR currency
- Automatic conversion to EUR (live rates, with USD/GBP fallback)
- Receipt upload endpoints:
  - Single upload: `POST /expenses/upload`
  - Batch upload: `POST /expenses/batch-upload`
- Receipt parsing hook (`RECEIPT_EXTRACTOR`) for AI extraction integrations

## Run

```bash
pip install -r requirements.txt
python app.py
```

## API summary

- `POST /auth/signup`
- `POST /auth/login`
- `POST /auth/2fa/setup`
- `GET /expenses`
- `POST /expenses`
- `POST /expenses/upload`
- `POST /expenses/batch-upload`

Use the `Authorization` header with the token returned by `POST /auth/login` for authenticated routes.
