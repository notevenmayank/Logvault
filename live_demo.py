"""
Sentinel Vault — Live Attack Demo

Run this ONE script in front of mentors/judges to show the complete PS 9
scenario end-to-end: logs get sealed into windows, hashed and chained,
anchored on the local blockchain, verified as Intact, then TWO simulated
attacks are run live and caught by the system.

PREREQUISITES before running this:
  1. "npx hardhat node" must be running in another terminal.
  2. The contract must already be deployed (python blockchain/deploy.py
     must have been run at least once against the currently running node).

Run with:
    python live_demo.py
"""
import hashlib
import json
import os
import random
import time
from datetime import datetime

import verification_core as vc
from web3 import Web3

LOG_FILE = "logs.txt"
CHAIN_FILE = "hash_chain.json"

EVENT_TYPES = [
    "AUTH_SUCCESS",
    "AUTH_FAILURE",
    "FILE_ACCESS",
    "FILE_MODIFIED",
    "PERMISSION_CHANGE",
]
USERS = ["alice", "bob", "carol", "dave_admin", "eva", "mallory"]
IPS = ["192.168.1.10", "10.0.4.15", "172.16.0.88", "198.51.100.24", "203.0.113.7"]


def line(sep="=", n=70):
    print(sep * n)


def heading(title):
    print()
    line()
    print(f" {title}")
    line()


def make_log_line():
    event = random.choice(EVENT_TYPES)
    user = random.choice(USERS)
    ip = random.choice(IPS)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{ts}] {event} user={user} ip={ip}\n"


def reset_state():
    heading("STEP 0: Resetting to a clean state")
    for f in [LOG_FILE, CHAIN_FILE]:
        if os.path.exists(f):
            os.remove(f)
    open(LOG_FILE, "w").close()
    with open(CHAIN_FILE, "w") as f:
        json.dump([], f)
    print("  logs.txt and hash_chain.json cleared.")


def seal_window(window_id, previous_hash, num_lines=5):
    """Writes num_lines fresh log lines, hashes them chained to the
    previous window's hash, and appends the record to hash_chain.json."""
    new_lines = [make_log_line() for _ in range(num_lines)]

    with open(LOG_FILE, "a") as f:
        f.writelines(new_lines)

    combined = previous_hash + "".join(new_lines)
    window_hash = hashlib.sha256(combined.encode()).hexdigest()

    entry = {
        "window_id": window_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "num_lines": num_lines,
        "previous_hash": previous_hash,
        "window_hash": window_hash,
    }

    with open(CHAIN_FILE, "r") as f:
        chain = json.load(f)
    chain.append(entry)
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

    print(f"  Window {window_id} sealed: {num_lines} lines, hash {window_hash[:16]}...")
    return window_hash


def anchor_all_pending():
    heading("Anchoring all sealed windows on the blockchain")
    contract, error = vc.get_contract()
    if contract is None:
        print(f"  ERROR: {error}")
        print("  Make sure 'npx hardhat node' is running and the contract is deployed.")
        raise SystemExit(1)

    w3 = Web3(Web3.HTTPProvider(vc.RPC_URL))
    sender = w3.eth.accounts[0]

    with open(CHAIN_FILE, "r") as f:
        chain = json.load(f)

    for entry in chain:
        wid = entry["window_id"]
        existing = contract.functions.getWindow(wid).call()
        if existing[4]:  # exists == True
            print(f"  Window {wid}: already anchored, skipping.")
            continue

        win_hash_bytes = bytes.fromhex(entry["window_hash"])
        prev_hash_bytes = bytes.fromhex(entry["previous_hash"])

        tx_hash = contract.functions.anchorWindow(
            wid, win_hash_bytes, prev_hash_bytes, entry["num_lines"]
        ).transact({"from": sender})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"  Window {wid}: anchored on-chain (tx {receipt.transactionHash.hex()[:16]}...)")


def print_statuses(label):
    heading(label)
    results, error = vc.get_all_window_statuses()
    if error:
        print(f"  (note: {error})")
    for r in results:
        print(f"  Window {r['window_id']}: {r['status']}")
    return results


def attack_modify_line():
    heading("ATTACK 1: Modifying a log line inside an already-anchored window")
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    # Window 1 occupies lines [5:10] (window 0 is lines [0:5])
    target_index = 6
    print(f"  Original line: {lines[target_index].strip()}")
    lines[target_index] = lines[target_index].replace("AUTH_SUCCESS", "AUTH_FAILURE") \
                                               .replace("AUTH_FAILURE", "AUTH_SUCCESS_FORGED")
    print(f"  Attacker changed it to: {lines[target_index].strip()}")

    with open(LOG_FILE, "w") as f:
        f.writelines(lines)


def attack_delete_window():
    heading("ATTACK 2: Deleting an entire window's record to erase evidence")
    with open(CHAIN_FILE, "r") as f:
        chain = json.load(f)

    target_wid = 2
    chain = [e for e in chain if e["window_id"] != target_wid]

    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

    print(f"  Window {target_wid}'s record deleted from hash_chain.json.")
    print(f"  (Its hash still exists on the blockchain, which is what will catch this.)")


def main():
    print()
    line("#")
    print(" SENTINEL VAULT — LIVE PS 9 ATTACK DEMONSTRATION")
    line("#")

    reset_state()

    heading("STEP 1: Generating and sealing 3 log windows")
    previous_hash = "0" * 64
    for wid in range(3):
        previous_hash = seal_window(wid, previous_hash)

    anchor_all_pending()

    print_statuses("STEP 2: Baseline verification — everything should be INTACT")

    attack_modify_line()
    print_statuses("STEP 3: Verification after Attack 1 — a modified line")

    attack_delete_window()
    print_statuses("STEP 4: Verification after Attack 2 — a deleted window")

    heading("DEMO COMPLETE")
    print("  Summary of what was just shown:")
    print("  - Logs were sealed into chained, hashed windows.")
    print("  - Each window's hash was anchored on the blockchain.")
    print("  - Verification against the blockchain confirmed all windows Intact.")
    print("  - A single modified log line was caught immediately as Tampered.")
    print("  - A fully deleted window was caught as Missing, because its")
    print("    on-chain proof still existed even though the local record was gone.")
    print()


if __name__ == "__main__":
    main()
