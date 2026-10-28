"""
Shared verification logic used by both verify_onchain.py (CLI) and
dashboard_app.py (web dashboard). Keeping this in one place means the
dashboard and the command-line tool always agree, since they call the
exact same function.
"""
import hashlib
import json
import os
import threading
from web3 import Web3
import ollama_explainer

RPC_URL = "http://127.0.0.1:8545"
ARTIFACT_PATH = os.path.join("blockchain", "artifacts", "contracts", "LogVault.sol", "LogVault.json")
ADDRESS_PATH = os.path.join("blockchain", "contract_address.txt")
CHAIN_FILE = "hash_chain.json"
LOG_FILE = "logs.txt"

# Explaining a tampered/missing window calls the local LLM, which can take
# many seconds (up to the 20s timeout) per window. If several windows need
# explaining at once (e.g. after a few simulate-attacks in a row), doing
# this synchronously inside /api/status makes the whole endpoint take
# minutes to respond -- which looks like the dashboard is stuck or like
# windows have "disappeared". So this is now fire-and-forget: a window
# that isn't explained yet gets a placeholder immediately, and a
# background thread fills in the real explanation for the NEXT poll to
# pick up from the cache. /api/status itself never waits on the LLM.
_incident_summary_cache = {}
_explaining_in_progress = set()
_cache_lock = threading.Lock()


def _explain_in_background(row, cache_key):
    try:
        summary = ollama_explainer.explain_window(row)
    except Exception:
        summary = None
    with _cache_lock:
        _incident_summary_cache[cache_key] = summary
        _explaining_in_progress.discard(cache_key)


def recompute_hash(lines, previous_hash_hex):
    combined = previous_hash_hex + "".join(lines)
    return hashlib.sha256(combined.encode()).hexdigest()


def find_tampered_lines(current_lines, stored_line_hashes, window_start_position):
    """
    Compares the current content of a window's lines against the
    per-line hashes that were recorded at hashing time, and returns
    exactly which line(s) changed.

    window_start_position is the 0-indexed position of this window's
    first line within the whole logs.txt file, so the line numbers
    returned are the real, global line numbers an operator can go look
    at directly, not just an offset within the window.

    If the line count itself differs (a line was deleted or inserted),
    that is reported too, since that is also tampering evidence even
    though it can't be pinned to one exact index past the point where
    the lists diverge.
    """
    if not stored_line_hashes:
        # older windows hashed before line-level tracking existed
        return None

    tampered = []

    if len(current_lines) != len(stored_line_hashes):
        tampered.append({
            "line_number": None,
            "reason": f"Line count changed: expected {len(stored_line_hashes)} lines, found {len(current_lines)}. "
                      f"A line was likely inserted or deleted inside this window."
        })

    for i, stored_hash in enumerate(stored_line_hashes):
        if i >= len(current_lines):
            break
        current_hash = hashlib.sha256(current_lines[i].encode()).hexdigest()
        if current_hash != stored_hash:
            tampered.append({
                "line_number": window_start_position + i + 1,  # 1-indexed, matches a text editor's line numbers
                "content": current_lines[i].rstrip("\n"),
            })

    return tampered


def get_contract():
    """Connects to the local blockchain and returns a ready-to-use contract object,
    or None (with a reason) if the chain or contract isn't available yet."""
    if not os.path.exists(ADDRESS_PATH):
        return None, "Contract not deployed yet. Run: python blockchain/deploy.py"

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        return None, "Cannot reach local blockchain at " + RPC_URL + ". Run: npx hardhat node"

    with open(ADDRESS_PATH, "r") as f:
        contract_address = f.read().strip()

    with open(ARTIFACT_PATH, "r") as f:
        artifact = json.load(f)

    contract = w3.eth.contract(address=contract_address, abi=artifact["abi"])
    return contract, None


def get_all_window_statuses():
    """
    Returns (results, error_message).

    results is a list of dicts, one per window known to the system (either
    from the local hash_chain.json record, or anchored on-chain, or both):
      window_id, status ("INTACT" / "TAMPERED" / "MISSING" / "NOT_ON_CHAIN"),
      num_lines, timestamp, onchain_hash (full hex), recomputed_hash (full hex)

    Windows that were anchored on-chain but whose record has since been
    removed from hash_chain.json are reported as MISSING — this is what
    catches an attacker deleting an entire window's evidence locally while
    its on-chain proof still exists.
    """
    contract, error = get_contract()

    chain = []
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, "r") as f:
            chain = json.load(f)

    if not chain and contract is None:
        return [], error or "No windows have been hashed yet. Run hash_windows.py first."

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            all_lines = f.readlines()
    else:
        all_lines = []

    local_window_ids = {entry["window_id"] for entry in chain}
    results = []
    position = 0

    for entry in chain:
        window_id = entry["window_id"]
        num_lines = entry["num_lines"]
        previous_hash = entry["previous_hash"]
        timestamp = entry["timestamp"]

        # Prefer the window's own stored start_line when it has one --
        # that makes its position correct even if an earlier window was
        # removed from the chain (e.g. a simulated "Missing" window).
        # Older entries written before this field existed fall back to
        # the running sum, same as before.
        if "start_line" in entry:
            window_start_position = entry["start_line"]
        else:
            window_start_position = position
        window_lines = all_lines[window_start_position: window_start_position + num_lines]
        position = window_start_position + num_lines

        recomputed_hex = recompute_hash(window_lines, previous_hash)

        row = {
            "window_id": window_id,
            "timestamp": timestamp,
            "num_lines": num_lines,
            "recomputed_hash": recomputed_hex,
            # raw content of this window's lines, for the dashboard's live
            # window viewer — trimmed so a huge window never bloats the API response
            "lines_preview": [line.rstrip("\n") for line in window_lines[:50]],
        }

        if contract is None:
            # Blockchain not reachable: fall back to comparing against the
            # local hash_chain.json record so the dashboard still shows
            # something useful, clearly labeled as a local-only check.
            local_hash = entry["window_hash"]
            row["onchain_hash"] = None
            row["source"] = "local_file_only"
            row["status"] = "INTACT" if recomputed_hex == local_hash else "TAMPERED"
            if row["status"] == "TAMPERED":
                row["tampered_lines"] = find_tampered_lines(window_lines, entry.get("line_hashes"), window_start_position)
            results.append(row)
            continue

        onchain_hash, onchain_prev, onchain_ts, onchain_lines, exists = contract.functions.getWindow(window_id).call()

        row["source"] = "blockchain"

        if not exists:
            row["onchain_hash"] = None
            row["status"] = "NOT_ON_CHAIN"
        else:
            onchain_hash_hex = onchain_hash.hex()
            row["onchain_hash"] = onchain_hash_hex
            row["status"] = "INTACT" if recomputed_hex == onchain_hash_hex else "TAMPERED"
            if row["status"] == "TAMPERED":
                row["tampered_lines"] = find_tampered_lines(window_lines, entry.get("line_hashes"), window_start_position)

        results.append(row)

    # Check for windows that exist on-chain but have vanished from the
    # local hash_chain.json entirely (an attacker trying to erase a whole
    # window's evidence, not just edit a line). Bounded probe so a missing
    # window can never cause an infinite loop.
    if contract is not None:
        highest_local = max(local_window_ids, default=-1)
        probe_upper_bound = highest_local + 5

        for probe_id in range(0, probe_upper_bound + 1):
            if probe_id in local_window_ids:
                continue

            onchain_hash, onchain_prev, onchain_ts, onchain_lines, exists = contract.functions.getWindow(probe_id).call()

            if exists:
                results.append({
                    "window_id": probe_id,
                    "timestamp": None,
                    "num_lines": onchain_lines,
                    "recomputed_hash": None,
                    "onchain_hash": onchain_hash.hex(),
                    "source": "blockchain",
                    "status": "MISSING",
                })

    results.sort(key=lambda r: r["window_id"])

    # Attach a human-readable incident summary to any Tampered/Missing
    # window. This runs AFTER the deterministic status is already decided
    # above — the LLM only explains the result, it never influences it.
    for row in results:
        if row["status"] not in ("TAMPERED", "MISSING"):
            row["incident_summary"] = None
            continue

        cache_key = (row["window_id"], row["status"], row.get("recomputed_hash"))
        with _cache_lock:
            if cache_key in _incident_summary_cache:
                row["incident_summary"] = _incident_summary_cache[cache_key]
            elif cache_key in _explaining_in_progress:
                row["incident_summary"] = None  # still being generated, check back next poll
            else:
                _explaining_in_progress.add(cache_key)
                row["incident_summary"] = None
                threading.Thread(target=_explain_in_background, args=(row, cache_key), daemon=True).start()

    return results, error
