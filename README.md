# Simple Credential Maker (FastAPI + SQLite)

This is a minimal credential / API key service built with **FastAPI** and **SQLite**.  
It lets you:

- Create credentials (API keys) with scopes and TTL
- Enforce basic policy (min length, max TTL)
- Enforce quotas per user
- Mark sensitive scopes as **pending** for approval
- Approve pending requests
- Revoke credentials
- (Dev only) Decrypt stored secrets to verify encryption

---

## Features

- 🔐 **Encrypted storage** of secrets using `cryptography.Fernet`
- 📦 **SQLite** backend (single file database)
- 🧩 **Policy-driven validation** via `policy.py`
- 🚦 **Approval flow** for sensitive scopes (`admin`, `write:*`)
- 🔢 **Quota**: max 5 active keys per principal (configurable)
- 🧰 **FastAPI** for HTTP endpoints (no Pydantic models required)

---

## Project Structure

You effectively have two main files:

- `main.py` (or similar name) – the FastAPI app:

  - DB setup and helpers  
  - `/credentials` create/list  
  - `/credentials/{cid}/revoke`  
  - `/requests/{rid}/approve`  
  - `/_debug/decrypt/{cid}`

- `policy.py` – policy configuration & checks:

  - `POLICY`: rules (allowed types, min length, max TTL, quotas, approval scopes)  
  - `validate_request(req)`  
  - `requires_approval(scopes)`

---

## Requirements

- Python 3.9+ (recommended)
- The following Python packages:

```bash
fastapi
uvicorn[standard]
cryptography
python-dotenv
