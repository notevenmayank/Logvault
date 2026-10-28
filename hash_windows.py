import hashlib
import json
import time
import os
from datetime import datetime

LOG_FILE = "logs.txt"
CHAIN_FILE = "hash_chain.json"
STATE_FILE = "hash_state.json"   # remembers where we left off, even after a restart
WINDOW_SECONDS = 30   # testing ke liye 30 sec rakha hai, baad mein 300 (5 min) kar denge

def load_chain():
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, "r") as f:
            return json.load(f)
    return []

def save_chain(chain):
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

def load_state():
    """Remembers how many lines of logs.txt we've already hashed, and the
    next window_id to use. This is what makes restarting this script safe
    -- it picks up exactly where it left off instead of re-reading
    logs.txt from the beginning.

    This used to track a raw byte position instead of a line count. That
    broke the moment any earlier line in the file changed length (e.g.
    the Simulate Attack feature replacing "LOGIN_SUCCESS" with a longer
    tampered string) -- every byte after that point shifts, so a saved
    byte offset silently starts pointing into the middle of the wrong
    line, corrupting every window hashed after that. Tracking a line
    count instead is immune to that: a line being edited in place doesn't
    change how many lines there are, so "lines already processed" stays
    correct even after a tamper rewrites the file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        if "lines_processed" not in state:
            # Migrating from the old byte-position format: we can't know
            # exactly how many lines that byte offset corresponded to
            # after the file may have been rewritten, so the safest
            # correct value is "how many lines the chain already
            # accounts for" -- hash_windows will simply pick up fresh
            # from there instead of guessing.
            state = {"lines_processed": 0, "next_window_id": state.get("next_window_id", 0)}
        return state
    return {"lines_processed": 0, "next_window_id": 0}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def get_last_hash(chain):
    if len(chain) == 0:
        return "0" * 64   # genesis hash, pehli window ke liye
    return chain[-1]["window_hash"]

def read_new_lines(lines_processed):
    if not os.path.exists(LOG_FILE):
        return [], lines_processed
    with open(LOG_FILE, "r") as f:
        all_lines = f.readlines()
    new_lines = all_lines[lines_processed:]
    new_lines_processed = len(all_lines)
    return new_lines, new_lines_processed

def hash_window(lines, previous_hash):
    combined = previous_hash + "".join(lines)
    return hashlib.sha256(combined.encode()).hexdigest()


def hash_each_line(lines):
    """One SHA-256 per individual line. Stored alongside the window hash
    so verification can later point at the exact line that changed,
    instead of only knowing which whole window is tampered."""
    return [hashlib.sha256(line.encode()).hexdigest() for line in lines]

def main():
    print(f"Hashing started. Window size = {WINDOW_SECONDS} seconds. Press Ctrl+C to stop.")
    chain = load_chain()
    state = load_state()
    lines_processed = state["lines_processed"]
    window_id = state["next_window_id"]

    if lines_processed > 0 or window_id > 0:
        print(f"Resuming after {lines_processed} already-hashed lines, next window will be #{window_id}.")

    while True:
        time.sleep(WINDOW_SECONDS)
        lines, lines_processed = read_new_lines(lines_processed)

        if not lines:
            print(f"Window {window_id}: no new logs, skipping.")
            save_state({"lines_processed": lines_processed, "next_window_id": window_id})
            continue

        previous_hash = get_last_hash(chain)
        window_hash = hash_window(lines, previous_hash)
        line_hashes = hash_each_line(lines)

        # Store this window's exact starting line in logs.txt, instead of
        # letting the dashboard infer it by summing every earlier window's
        # line count at read time. That inference breaks the moment ANY
        # earlier window is removed (e.g. to demo a "Missing" window) --
        # every window after it would then be computed against the wrong
        # lines. Storing it explicitly makes each window's position
        # independent of whether other windows still exist.
        start_line = sum(e["num_lines"] for e in chain)

        entry = {
            "window_id": window_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "num_lines": len(lines),
            "start_line": start_line,
            "previous_hash": previous_hash,
            "window_hash": window_hash,
            "line_hashes": line_hashes,
        }

        chain.append(entry)
        save_chain(chain)

        print(f"Window {window_id}: {len(lines)} lines hashed -> {window_hash[:16]}...")
        window_id += 1

        save_state({"lines_processed": lines_processed, "next_window_id": window_id})

if __name__ == "__main__":
    main()
