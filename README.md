# 🔑 Credential Manager (Full Stack)

A secure, policy-driven API Key management system. This application allows users to request API credentials with specific scopes, enforces administrative approval for sensitive permissions, and securely stores secrets using **Fernet (AES) encryption**.

![Project Status](https://img.shields.io/badge/Status-Live-success)
![Stack](https://img.shields.io/badge/Stack-FastAPI%20%7C%20VanillaJS-blue)
![Deployment](https://img.shields.io/badge/Deploy-Render%20%2B%20Vercel-purple)

## 🚀 Live Demo

- **Frontend (User UI):** [https://credential-manager.vercel.app](https://credential-manager.vercel.app) *(Replace with your Vercel Link)*
- **Backend (API):** [https://cred-manager-api.onrender.com](https://cred-manager-api.onrender.com) *(Replace with your Render Link)*

> **Note:** The backend is hosted on Render's Free Tier. If the API doesn't respond immediately, please wait **30-60 seconds** for the server to wake up from sleep mode.

---

## ✨ Key Features

### 🛡️ Security & Architecture
- **Fernet Encryption:** API Secrets are encrypted before being stored in the database. Even the database admin cannot see raw keys.
- **Role Separation:** Distinct interfaces for **Users** (Requesting) and **Admins** (Approving).
- **CORS Protection:** Configured to only allow requests from the trusted frontend.

### ⚙️ Policy Engine
- **Auto-Approval:** Read-only scopes (e.g., `read:users`) are issued immediately.
- **Admin Approval:** Sensitive scopes (e.g., `admin`, `write:*`) trigger a "Pending" state requiring manual approval.
- **Quotas:** Limits users to a maximum of 5 active keys.

### 🖥️ UI/UX
- **Dual Dashboard:** Switch between User and Admin views via sidebar navigation.
- **Secure Key Claim:** Keys are never displayed immediately. Users receive an ID and must explicitly "Check Status" to claim the decrypted secret.

---

## 🛠️ Tech Stack

**Backend:**
- **Python 3.10+**
- **FastAPI:** High-performance web framework.
- **SQLite:** Lightweight relational database.
- **Cryptography:** For Fernet symmetric encryption.

**Frontend:**
- **HTML5 / CSS3:** Custom responsive design (Flexbox/Grid).
- **Vanilla JavaScript:** `fetch` API for backend communication.

**DevOps:**
- **Render:** Python backend hosting.
- **Vercel:** Static frontend hosting.

---

## 📸 Usage Workflow

### 1. User Workflow
1.  Navigate to the **User Panel**.
2.  Enter a **Principal Name** (username) and **Scopes**.
3.  Click **Request Key**.
    * *Safe Scopes:* You get an ID. Use "Check Status" to reveal the key immediately.
    * *Risky Scopes (e.g., `admin`):* You get an ID. "Check Status" will show "Pending".

### 2. Admin Workflow
1.  Switch to the **Admin Panel**.
2.  View the **All Credentials** list.
3.  Copy a "Pending" Request ID.
4.  Paste it into the **Approve Request** box and click Approve.
5.  (Optional) Use **Revoke** to disable compromised keys.

---

## 💻 Local Installation

If you want to run this project locally:

### 1. Backend Setup
```bash
# Clone the repo
git clone [https://github.com/yourusername/credential-manager.git](https://github.com/yourusername/credential-manager.git)
cd credential-manager

# Create virtual env (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload
