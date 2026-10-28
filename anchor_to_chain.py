"""
Sentinel Vault — continuous anchoring.

Watches hash_chain.json and anchors any window that isn't on the
blockchain yet. Runs forever: every few seconds it re-reads the chain
file (hash_windows.py keeps appending to it) and anchors whatever is
new, so you never have to manually re-run this after every window.

Run with:  python anchor_to_chain.py
Press Ctrl+C to stop.
"""
import json
import os
import time
from web3 import Web3

RPC_URL = "http://127.0.0.1:8545"
ARTIFACT_PATH = os.path.join("blockchain", "artifacts", "contracts", "LogVault.sol", "LogVault.json")
ADDRESS_PATH = os.path.join("blockchain", "contract_address.txt")
CHAIN_FILE = "hash_chain.json"
POLL_SECONDS = 8  # how often to check for newly-hashed windows


def connect():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))

    if not w3.is_connected():
        print("ERROR: Could not connect to local blockchain at " + RPC_URL)
        print("Make sure 'npx hardhat node' is running in another terminal.")
        return None, None, None

    if not os.path.exists(ADDRESS_PATH):
        print("ERROR: contract_address.txt not found. Run: python blockchain\\deploy.py")
        return None, None, None

    with open(ADDRESS_PATH, "r") as f:
        contract_address = f.read().strip()

    with open(ARTIFACT_PATH, "r") as f:
        artifact = json.load(f)

    contract = w3.eth.contract(address=contract_address, abi=artifact["abi"])
    sender = w3.eth.accounts[0]
    return w3, contract, sender


def anchor_pending(w3, contract, sender):
    if not os.path.exists(CHAIN_FILE):
        return 0, 0

    with open(CHAIN_FILE, "r") as f:
        chain = json.load(f)

    newly_anchored = 0
    already_anchored = 0

    for entry in chain:
        window_id = entry["window_id"]

        # Ask the blockchain itself whether this window exists, instead of
        # trusting a local tracking file.
        existing = contract.functions.getWindow(window_id).call()
        exists_onchain = existing[4]

        if exists_onchain:
            already_anchored += 1
            continue

        window_hash_bytes = bytes.fromhex(entry["window_hash"])
        previous_hash_bytes = bytes.fromhex(entry["previous_hash"])
        num_lines = entry["num_lines"]

        try:
            tx_hash = contract.functions.anchorWindow(
                window_id,
                window_hash_bytes,
                previous_hash_bytes,
                num_lines,
            ).transact({"from": sender})

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

            print(f"Window {window_id}: anchored on-chain (tx {receipt.transactionHash.hex()[:16]}...)")
            newly_anchored += 1
        except Exception as e:
            print(f"Window {window_id}: FAILED to anchor — {e}")

    return newly_anchored, already_anchored


def main():
    w3, contract, sender = connect()
    if contract is None:
        return

    print(f"Auto-anchoring started. Checking for new windows every {POLL_SECONDS} seconds. Press Ctrl+C to stop.\n")

    while True:
        newly, already = anchor_pending(w3, contract, sender)
        if newly:
            print(f"  -> {newly} new window(s) anchored just now. ({already} already were.)")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
