# Sentinel Vault — Backend & Blockchain Core

The operational backend, blockchain anchoring service, and real-time verification engine for **Sentinel Vault**, a tamper-proof security log vault that SHA-256 hash-chains and blockchain-anchors every log window so unauthorized edits are pinpointed down to the exact line.

---

## 🛠 Tech Stack

| Technology | Role |
|---|---|
| **Python 3.12** | Core language for verification logic, API server, and automation agents |
| **Flask 3.1 & Flask-CORS** | Web server hosting the operational dashboard and cross-origin REST APIs |
| **SQLite 3** | Local credential store (`users.db`) for user registration and authentication |
| **Werkzeug Security** | Secure password hashing (`scrypt`/`pbkdf2`) and verification |
| **Solidity & Hardhat** | Ethereum-compatible smart contract (`LogVault.sol`) and local dev network |
| **Web3.py** | JSON-RPC blockchain client anchoring hashes and reading trusted records |
| **Hashlib (SHA-256)** | Cryptographic window hashing and continuous chain computation |
| **Ollama (Llama 3 / Mistral)** | Local offline LLM investigator explaining verification verdicts in plain language |
| **Faker** | Procedural generation of realistic multi-source security events |
| **Twilio / Webhooks** | Real-time voice and push notification dispatcher on detected tampering |

---

## 📂 File-by-File Breakdown

```
graphite-logvault/
├── dashboard_app.py        # Main Flask application (port 5000); serves dashboard UI and /api/* endpoints
├── auth.py                 # Authentication blueprint (/api/auth) handling signup, login, logout, and session check
├── verification_core.py    # Independent verification engine; detects INTACT, TAMPERED, MISSING, and pinpointed line numbers
├── hash_windows.py         # Batch log processing worker; computes SHA-256 window hashes chained to the previous window
├── anchor_to_chain.py      # Blockchain worker; reads unsealed windows from hash_chain.json and writes them to LogVault.sol
├── verify_onchain.py       # Reads on-chain hashes via Web3 and compares against recomputed local log hashes
├── verify.py               # Lightweight CLI tool for quick terminal-based hash chain verification
├── log_generator.py        # Background service generating continuous, realistic enterprise security logs using Faker
├── ingest_server.py        # Microservice accepting external JSON log streams and safely appending them to logs.txt
├── send_sample_logs.py     # Utility script for emitting synthetic test log batches to the ingest server
├── ollama_explainer.py     # Connects to local Ollama instance to translate deterministic tampering verdicts into plain English
├── soc_agent.py            # Autonomous SOC AI agent monitoring alerts and orchestrating triage
├── notify.py               # Dispatcher firing voice calls, SMS, or webhooks once per tampered window incident
├── cloud_sync.py           # Off-site cloud backup and synchronization utility for sealed hash state
├── live_demo.py            # Automated end-to-end demonstration script orchestrating logs, hashing, anchoring, and attack
├── users.db                # SQLite database storing user accounts (id, email UNIQUE, password_hash, created_at)
├── logs.txt                # Append-only primary log file storing raw event records
├── hash_chain.json         # Persisted local chain recording window hashes, timestamps, and line offsets
├── hash_state.json         # State cursor tracking the last processed line index in logs.txt
├── ARCHITECTURE.md         # Detailed architectural documentation on cryptographic chaining and blockchain immutability
├── blockchain/             # Hardhat project directory
│   ├── contracts/
│   │   └── LogVault.sol    # Smart contract permanently storing immutable window hashes (anchorWindow, getWindow)
│   ├── scripts/            # Contract deployment and inspection scripts
│   └── hardhat.config.js   # Local blockchain network settings
├── templates/
│   └── dashboard.html      # Jinja2 template for the Flask-rendered operational dashboard
└── static/                 # Styles, scripts, and media for the Flask dashboard UI
```

---

## 🔄 Core Pipeline & Architecture

```
[Log Generators / Ingest]
           │
           ▼
       logs.txt (Raw append-only event stream)
           │
           ▼
    hash_windows.py
       - Computes: window_hash = SHA256(prev_hash + window_lines)
       - Appends to hash_chain.json
           │
           ▼
    anchor_to_chain.py
       - Calls LogVault.sol::anchorWindow(id, hash, prevHash, lines)
       - Hardhat blockchain permanently locks hash (cannot be overwritten)
           │
           ▼
    verification_core.py (queried by dashboard_app.py)
       - Recomputes hash from current logs.txt
       - Compares with immutable blockchain record
       - Verdict: INTACT | TAMPERED | MISSING
       - Pinpoints exact line number where content was modified
```

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | `GET` | Returns live integrity counts (`intact`, `tampered`, `missing`) and window arrays |
| `/api/recent-logs` | `GET` | Returns the latest 25 log lines with 1-indexed line numbers for real-time tails |
| `/api/llm-status` | `GET` | Reports whether local Ollama AI is reachable and which model is loaded |
| `/api/simulate-attack`| `POST` | Forges a line in the latest intact window to immediately demo real tamper detection |
| `/api/auth/signup` | `POST` | Registers a new user with password hashing; establishes session cookie |
| `/api/auth/login` | `POST` | Validates credentials against SQLite database; issues signed session cookie |
| `/api/auth/logout` | `POST` | Clears current Flask session |
| `/api/auth/me` | `GET` | Checks if caller has an active session cookie (`authenticated: true/false`) |

---

## 🚀 Running the Backend

### 1. Setup Environment
```bash
cd graphite-logvault
python -m venv venv
venv\Scripts\activate       # On Windows
pip install -r requirements.txt   # Or pip install flask flask-cors web3 faker requests
```

### 2. Start the Local Blockchain (Optional for On-Chain Mode)
```bash
cd blockchain
npx hardhat node
npx hardhat run scripts/deploy.js --network localhost
```

### 3. Run the Flask Server
```bash
python dashboard_app.py
```
The operational dashboard will run on **`http://localhost:5000`**.
