"""
Sentinel Vault — Log Ingestion API

This is the front door of the vault. Any system (a firewall, an app
server, an AWS account, a database, whatever) sends its security events
here over HTTP, authenticated with an API key. Every accepted event is
appended to logs.txt as one JSON line — exactly the same file that
hash_windows.py is already watching and chunking into 30-second windows.

Nothing about the hashing/blockchain/dashboard pipeline needs to change
for this: hash_windows.py hashes raw lines of text, so it does not care
whether those lines are plain text or JSON.

Run with:  python ingest_server.py
Listens on: http://localhost:8001

Send a log with curl:
  curl -X POST http://localhost:8001/events ^
    -H "X-API-Key: sk_demo001" ^
    -H "Content-Type: application/json" ^
    -d "{\"timestamp\": 1730000000, \"user_id\": \"admin_01\", \"action\": \"LOGIN_SUCCESS\", \"source_ip\": \"192.168.1.50\"}"
"""
from flask import Flask, request, jsonify
import json
import time

app = Flask(__name__)

LOG_FILE = "logs.txt"

# Demo API keys. In a real deployment each client (each source system)
# would get its own key from a proper secrets store, not a hardcoded
# dict — this is fine for a hackathon demo.
API_KEYS = {
    "sk_demo001": "generic_demo_client",
    "sk_hdfc001": "hdfc_bank_demo",
}

# Attack-specific actions and the suspicion score they add, straight
# from the PS9 log-type spec. A normal event scores 0.
ATTACK_SCORES = {
    "LOGIN_FAILED": 20,
    "DB_SUSPICIOUS_QUERY": 30,
    "WEB_ATTACK_DETECTED": 30,
    "PORT_SCAN_DETECTED": 25,
    "TRAFFIC_SPIKE": 35,
    "BULK_DOWNLOAD": 40,
    "ADMIN_ACTION_BY_USER": 40,
    "MALWARE_DETECTED": 35,
    "SENSITIVE_ACCESS": 30,
}


def check_api_key():
    """Returns the client name for a valid key, or None if the key is
    missing/invalid."""
    key = request.headers.get("X-API-Key")
    if not key:
        return None
    return API_KEYS.get(key)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "sentinel-ingest"})


@app.route("/events", methods=["POST"])
def ingest_event():
    client = check_api_key()
    if client is None:
        return jsonify({"success": False, "error": "Missing or invalid X-API-Key"}), 401

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"success": False, "error": "Request body must be valid JSON"}), 400

    # Only two fields are actually required — everything else is
    # optional, per the log-type spec ("System accepts ANY event with
    # timestamp + action").
    if "timestamp" not in body or "action" not in body:
        return jsonify({"success": False, "error": "Both 'timestamp' and 'action' are required fields"}), 400

    action = str(body["action"]).upper()
    suspicious_score = ATTACK_SCORES.get(action, 0)

    record = {
        "timestamp": body["timestamp"],
        "user_id": body.get("user_id", "unknown"),
        "action": action,
        "source_ip": body.get("source_ip", "unknown"),
        "details": body.get("details", {}),
        "suspicious_score": suspicious_score,
        "client": client,
        "received_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    return jsonify({
        "success": True,
        "message": "Event logged and queued for the next hashing window.",
        "suspicious_score": suspicious_score,
        "suspicious": suspicious_score > 0,
    }), 200


if __name__ == "__main__":
    print("Sentinel Vault ingest API starting on http://localhost:8001")
    print("Send logs to POST /events with header X-API-Key: sk_demo001")
    app.run(debug=True, port=8001)
