import hashlib
import json
import os
from web3 import Web3

RPC_URL = "http://127.0.0.1:8545"
ARTIFACT_PATH = os.path.join("blockchain", "artifacts", "contracts", "LogVault.sol", "LogVault.json")
ADDRESS_PATH = os.path.join("blockchain", "contract_address.txt")
CHAIN_FILE = "hash_chain.json"
LOG_FILE = "logs.txt"

def recompute_hash(lines, previous_hash_hex):
    combined = previous_hash_hex + "".join(lines)
    return hashlib.sha256(combined.encode()).hexdigest()

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))

    if not w3.is_connected():
        print("ERROR: Could not connect to local blockchain at " + RPC_URL)
        return

    with open(ADDRESS_PATH, "r") as f:
        contract_address = f.read().strip()

    with open(ARTIFACT_PATH, "r") as f:
        artifact = json.load(f)

    contract = w3.eth.contract(address=contract_address, abi=artifact["abi"])

    with open(CHAIN_FILE, "r") as f:
        chain = json.load(f)

    with open(LOG_FILE, "r") as f:
        all_lines = f.readlines()

    print(f"Verifying {len(chain)} windows against on-chain records...\n")

    position = 0
    for entry in chain:
        window_id = entry["window_id"]
        num_lines = entry["num_lines"]
        previous_hash = entry["previous_hash"]

        window_lines = all_lines[position : position + num_lines]
        position += num_lines

        recomputed_hex = recompute_hash(window_lines, previous_hash)

        onchain_hash, onchain_prev, onchain_ts, onchain_lines, exists = contract.functions.getWindow(window_id).call()

        if not exists:
            print(f"Window {window_id}: NOT ON-CHAIN (never anchored)")
            continue

        onchain_hash_hex = onchain_hash.hex()

        if recomputed_hex == onchain_hash_hex:
            print(f"Window {window_id}: INTACT (matches blockchain record)")
        else:
            print(f"Window {window_id}: TAMPERED  (on-chain: {onchain_hash_hex[:16]}..., current logs: {recomputed_hex[:16]}...)")

if __name__ == "__main__":
    main()
