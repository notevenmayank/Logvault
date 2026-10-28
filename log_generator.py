"""
Sentinel Vault — background log generator.

Writes synthetic security events straight to logs.txt (same file the
ingest API appends to), in the same JSON-line format, so the dashboard
sees one continuous, realistic stream even when nobody is calling the
API by hand. Useful to keep traffic flowing during a demo.
"""
import json
import random
import time
from faker import Faker

fake = Faker()

LOG_FILE = "logs.txt"

# Normal, everyday events across the 8 log categories from the spec.
NORMAL_EVENTS = [
    ("auth", "LOGIN_SUCCESS"),
    ("auth", "LOGOUT"),
    ("auth", "MFA_VERIFIED"),
    ("file", "FILE_READ"),
    ("file", "FILE_WRITE"),
    ("file", "FOLDER_ACCESS"),
    ("database", "DB_SELECT"),
    ("database", "DB_INSERT"),
    ("network", "CONNECTION_ALLOWED"),
    ("network", "VPN_CONNECTION"),
    ("system", "BACKUP_COMPLETED"),
    ("system", "SERVICE_STARTED"),
    ("application", "API_REQUEST"),
    ("application", "USER_REGISTERED"),
    ("cloud", "EC2_INSTANCE_STARTED"),
    ("cloud", "S3_BUCKET_ACCESSED"),
]

# Rarer, attack-flavored events — these carry a suspicious_score > 0,
# same scoring the ingest API applies, so the dashboard/LLM layer has
# something interesting to flag even without anyone hitting /events.
ATTACK_EVENTS = [
    ("auth", "LOGIN_FAILED", 20),
    ("database", "DB_SUSPICIOUS_QUERY", 30),
    ("network", "PORT_SCAN_DETECTED", 25),
    ("network", "TRAFFIC_SPIKE", 35),
    ("file", "BULK_DOWNLOAD", 40),
    ("security", "ADMIN_ACTION_BY_USER", 40),
    ("security", "MALWARE_DETECTED", 35),
    ("security", "SENSITIVE_ACCESS", 30),
]


def generate_event():
    # roughly 1 in 8 events is an attack-flavored one
    if random.randint(1, 8) == 1:
        source, action, score = random.choice(ATTACK_EVENTS)
    else:
        source, action = random.choice(NORMAL_EVENTS)
        score = 0

    record = {
        "timestamp": int(time.time()),
        "user_id": fake.user_name(),
        "action": action,
        "source_ip": fake.ipv4(),
        "details": {"source_category": source},
        "suspicious_score": score,
        "client": "log_generator",
        "received_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return record


def main():
    print("Log generator started. Press Ctrl+C to stop.")
    with open(LOG_FILE, "a") as f:
        while True:
            record = generate_event()
            line = json.dumps(record)
            print(line)
            f.write(line + "\n")
            f.flush()
            time.sleep(random.uniform(1, 3))


if __name__ == "__main__":
    main()
