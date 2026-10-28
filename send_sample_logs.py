"""
Sentinel Vault — demo client for the ingest API.

Sends a handful of sample events, across different log categories, to
the running ingest_server.py (POST /events), authenticated with an API
key. Use this to show mentors that any external system can report logs
into the vault, not just the internal generator.

Run with:  python send_sample_logs.py
(ingest_server.py must already be running on port 8001)
"""
import time
import requests

API_URL = "http://localhost:8001/events"
API_KEY = "sk_demo001"

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}

SAMPLE_EVENTS = [
    {
        "timestamp": int(time.time()),
        "user_id": "admin_01",
        "action": "LOGIN_SUCCESS",
        "source_ip": "192.168.1.50",
        "details": {"method": "password", "mfa_used": True, "location": "Mumbai"},
    },
    {
        "timestamp": int(time.time()),
        "user_id": "admin_01",
        "action": "FILE_READ",
        "source_ip": "192.168.1.50",
        "details": {"file_path": "/var/www/html/index.html", "file_size": 2048},
    },
    {
        "timestamp": int(time.time()),
        "user_id": "api_user",
        "action": "DB_UPDATE",
        "source_ip": "10.0.0.50",
        "details": {"table": "salary_records", "records_affected": 1},
    },
    {
        "timestamp": int(time.time()),
        "user_id": "firewall_01",
        "action": "CONNECTION_BLOCKED",
        "source_ip": "1.2.3.4",
        "details": {"target_ip": "192.168.1.100", "port": 22, "reason": "Blocked by rule"},
    },
    {
        # this one is an attack-flavored action, so the API will score it
        "timestamp": int(time.time()),
        "user_id": "hacker_x",
        "action": "DB_SUSPICIOUS_QUERY",
        "source_ip": "203.0.113.42",
        "details": {"threat_type": "SQL_INJECTION", "target_url": "/api/users?id=1 OR 1=1"},
    },
]


def main():
    print(f"Sending {len(SAMPLE_EVENTS)} sample events to {API_URL}\n")
    for event in SAMPLE_EVENTS:
        try:
            resp = requests.post(API_URL, headers=HEADERS, json=event, timeout=5)
            result = resp.json()
            score = result.get("suspicious_score", 0)
            flag = " <-- SUSPICIOUS" if score > 0 else ""
            print(f"  {event['action']:<25} -> status {resp.status_code}, score {score}{flag}")
        except requests.exceptions.ConnectionError:
            print("Could not reach ingest_server.py. Is it running on port 8001?")
            return
        time.sleep(0.3)

    print("\nDone. These events are now in logs.txt and will be picked up by the next hashing window.")


if __name__ == "__main__":
    main()
