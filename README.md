# Sakshya - private, tamper-evident evidence vault
Run: `pip install -r requirements.txt && uvicorn app:app --port 8000` then open http://localhost:8000
Stack: FastAPI, SQLite, vanilla JS, Web Crypto (SHA-256), ReportLab, qrcode.
Features: PIN + duress PIN, client-side hashing, hash-chained timeline, integrity audit, PDF report with QR, public verify page.
Limits (roadmap): trusted timestamping (RFC 3161), at-rest encryption, BSA Section 63 certificate format, OTP login.

## Third-party libraries
FastAPI, Uvicorn, python-multipart, ReportLab, qrcode, Pillow (all open source). Browser hashing uses the built-in Web Crypto API.
