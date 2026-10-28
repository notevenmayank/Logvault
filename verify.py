import hashlib
import json

CHAIN_FILE = "hash_chain.json"
LOG_FILE = "logs.txt"

def load_chain():
    with open(CHAIN_FILE, "r") as f:
        return json.load(f)

def recompute_hash(lines, previous_hash):
    combined = previous_hash + "".join(lines)
    return hashlib.sha256(combined.encode()).hexdigest()

def main():
    chain = load_chain()

    with open(LOG_FILE, "r") as f:
        all_lines = f.readlines()

    print(f"Total windows on record: {len(chain)}")
    print("Verifying each window...\n")

    position = 0
    for entry in chain:
        window_id = entry["window_id"]
        num_lines = entry["num_lines"]
        stored_hash = entry["window_hash"]
        previous_hash = entry["previous_hash"]

        window_lines = all_lines[position : position + num_lines]
        position += num_lines

        recomputed = recompute_hash(window_lines, previous_hash)

        if recomputed == stored_hash:
            print(f"Window {window_id}: INTACT")
        else:
            print(f"Window {window_id}: TAMPERED  (expected {stored_hash[:16]}..., got {recomputed[:16]}...)")

if __name__ == "__main__":
    main()