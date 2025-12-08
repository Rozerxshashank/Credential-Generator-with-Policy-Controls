import os
import json
import sqlite3
import secrets
import uuid
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import policy

load_dotenv()

# Setup Encryption Key
MASTER_KEY = os.getenv("MASTER_KEY")
if not MASTER_KEY:
    MASTER_KEY = Fernet.generate_key().decode() #only for demo when not using .env for master key

fernet = Fernet(MASTER_KEY.encode())
DB_PATH = os.getenv("DB_PATH", "data.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY,
        principal TEXT,
        type TEXT,
        scopes TEXT,
        created_at TEXT,
        expires_at TEXT,
        status TEXT,
        secret_enc TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

def now_iso():
    return datetime.utcnow().isoformat() + "Z"
def make_id():
    return str(uuid.uuid4())
def make_token(length=40):
    return secrets.token_urlsafe(length)[:length]
def encrypt_secret(secret):
    return fernet.encrypt(secret.encode()).decode()
def decrypt_secret(enc):
    return fernet.decrypt(enc.encode()).decode()

app = FastAPI(title="Simple Credential Maker")


#-----------------------------------------
origins = [
    "https://credential-generator-with-policy-co.vercel.app/" 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    
    allow_credentials=False,  
    allow_methods=["*"],
    allow_headers=["*"],
)
# ---------------------------------------

@app.post("/credentials")
def create_credential(req: dict = Body(...)):
    data = {
        "principal": req.get("principal", ""),
        "type": req.get("type", "api_key"),
        "scopes": req.get("scopes", []) or [],
        "ttl_seconds": int(req.get("ttl_seconds", 3600)),
        "length": int(req.get("length", 40))
    }

    if not data["principal"]:
        raise HTTPException(status_code=400, detail="principal_required")

    ok, why = policy.validate_request(data)
    if not ok:
        raise HTTPException(status_code=400, detail=why)

    need_approval, reason = policy.requires_approval(data.get("scopes", []))

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as c FROM credentials WHERE principal=? AND status='active'", (data["principal"],))
    count = cur.fetchone()["c"]
    if count >= policy.POLICY["quotas"]["max_active_per_principal"]:
        conn.close()
        raise HTTPException(status_code=403, detail="quota_exceeded")

    if need_approval:
        cid = make_id()
        created = now_iso()
        expires = (datetime.utcnow() + timedelta(seconds=data["ttl_seconds"])).isoformat() + "Z"
        cur.execute(
            "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (cid, data["principal"], data["type"], json.dumps(data["scopes"]), created, expires, "pending", None)
        )
        conn.commit()
        conn.close()
        return {"status": "pending", "request_id": cid, "reason": reason, "id": cid}

    token = make_token(data["length"])
    encrypted = encrypt_secret(token)
    cid = make_id()
    created = now_iso()
    expires = (datetime.utcnow() + timedelta(seconds=data["ttl_seconds"])).isoformat() + "Z"

    cur.execute(
        "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (cid, data["principal"], data["type"], json.dumps(data["scopes"]), created, expires, "active", encrypted)
    )
    conn.commit()
    conn.close()

    return {"status": "issued", "credential_id": cid, "secret": token, "expires_at": expires, "id": cid}


@app.get("/credentials")
def list_credentials():
    conn = get_conn()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM credentials").fetchall()
    conn.close()

    all_data = []
    for r in rows:
        scopes = []
        try:
            scopes = json.loads(r["scopes"]) if r["scopes"] else []
        except Exception:
            scopes = []
        all_data.append({
            "id": r["id"],
            "principal": r["principal"],
            "type": r["type"],
            "scopes": scopes,
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "status": r["status"]
        })
    return all_data


@app.post("/credentials/{cid}/revoke")
def revoke(cid: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM credentials WHERE id=?", (cid,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="not_found")

    cur.execute("UPDATE credentials SET status='revoked' WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    return {"status": "revoked", "credential_id": cid}


@app.post("/requests/{rid}/approve")
def approve(rid: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM credentials WHERE id=?", (rid,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="not_found")

    if row["status"] != "pending":
        conn.close()
        raise HTTPException(status_code=400, detail="not_pending")

    token = make_token(40)
    encrypted = encrypt_secret(token)

    cur.execute("UPDATE credentials SET status='active', secret_enc=? WHERE id=?", (encrypted, rid))
    conn.commit()
    conn.close()

    return {"status": "issued", "credential_id": rid, "secret": token, "expires_at": row["expires_at"]}


@app.get("/_debug/decrypt/{cid}")
def debug_decrypt(cid: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT secret_enc FROM credentials WHERE id=?", (cid,))
    row = cur.fetchone()
    conn.close()

    if not row or not row["secret_enc"]:
        raise HTTPException(status_code=404, detail="not_found_or_no_secret")

    return {"credential_id": cid, "secret_plaintext": decrypt_secret(row["secret_enc"])}