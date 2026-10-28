"""
Sentinel Vault — Cloud Sync (Pillar 4, simulated)

Watches for TAMPERED/MISSING windows and writes a sanitized incident
record for each one to cloud_sync_log.json, in exactly the shape that
would be sent to a real cloud backend (Supabase/Firebase) — just
without the network call.

Why simulated instead of wired to a real Supabase/Firebase project for
this demo:
  1. It needs a real account + API keys, which is outside what this
     script can set up on its own.
  2. A live demo should never depend on conference WiFi being reliable.

The architecture is deliberately written so swapping this out for a
real network call later is a small change — see `push_to_cloud()`
below, which is the one function you'd replace with an actual
supabase-py or firebase-admin call.

Only sanitized fields are sent: window_id, status, timestamp, and
line count — never raw log content or hashes, same privacy posture a
real incident-reporting pipeline would use.

Run with:  python cloud_sync.py
Press Ctrl+C to stop.
"""
import json
import os
import time

import verification_core

SYNC_LOG_FILE = "cloud_sync_log.json"
POLL_SECONDS = 10


def load_synced_ids():
    if not os.path.exists(SYNC_LOG_FILE):
        return set(), []
    with open(SYNC_LOG_FILE, "r") as f:
        records = json.load(f)
    return {r["window_id"] for r in records}, records


def push_to_cloud(record):
    """
    This is the one function you'd swap for a real call, e.g.:
        supabase.table("incidents").insert(record).execute()
    For the demo it just appends to a local JSON file instead, so the
    whole pipeline works fully offline.
    """
    _, records = load_synced_ids()
    records.append(record)
    with open(SYNC_LOG_FILE, "w") as f:
        json.dump(records, f, indent=2)


def sanitize(window):
    """Only the fields a cloud incident dashboard actually needs —
    never raw log lines, never full hashes."""
    return {
        "window_id": window["window_id"],
        "status": window["status"],
        "num_lines": window.get("num_lines"),
        "synced_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def main():
    print(f"Cloud sync (simulated) started. Checking every {POLL_SECONDS}s. Press Ctrl+C to stop.")
    print(f"Writing sanitized incident records to {SYNC_LOG_FILE}\n")

    while True:
        results, _ = verification_core.get_all_window_statuses()
        synced_ids, _ = load_synced_ids()

        for window in results:
            if window["status"] in ("TAMPERED", "MISSING") and window["window_id"] not in synced_ids:
                record = sanitize(window)
                push_to_cloud(record)
                print(f"Synced to cloud (simulated): window {window['window_id']} ({window['status']})")
                synced_ids.add(window["window_id"])

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
