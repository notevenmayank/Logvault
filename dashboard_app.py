"""
Sentinel Vault Dashboard â€” a small Flask app that shows every log window's
integrity status (Intact / Tampered / Missing / Not on chain) live, by
calling the same verification logic used by the command-line tool.

Run with:  python dashboard_app.py
Then open: http://127.0.0.1:5000
"""
from flask import Flask, jsonify, render_template
from flask_cors import CORS
import json
import os
import verification_core
import ollama_explainer
import notify
from auth import auth_bp

# Tracks which TAMPERED/MISSING window_ids we've already alerted on, so a
# phone call/push notification only fires once per incident, not on every
# 5-second poll. Lives in memory, so it resets if the server restarts --
# fine for a demo.
_alerted_window_ids = set()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sentinel-vault-secret-key-super-secure-2026")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# Allows the separate React/Vite landing page (localhost:5173 during dev)
# to call these /api/* endpoints with session credentials
CORS(app, resources={r"/api/*": {"origins": "*", "supports_credentials": True}})
app.register_blueprint(auth_bp)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    """
    Returns live window statuses as JSON. The dashboard page polls this
    endpoint so the page always reflects the real, current state, never
    hardcoded sample data.
    """
    results, error = verification_core.get_all_window_statuses()

    for r in results:
        if r["status"] in ("TAMPERED", "MISSING") and r["window_id"] not in _alerted_window_ids:
            _alerted_window_ids.add(r["window_id"])
            notify.alert_new_incident(r["window_id"], r["status"])

    intact = sum(1 for r in results if r["status"] == "INTACT")
    tampered = sum(1 for r in results if r["status"] == "TAMPERED")
    missing = sum(1 for r in results if r["status"] == "MISSING")
    not_on_chain = sum(1 for r in results if r["status"] == "NOT_ON_CHAIN")

    return jsonify({
        "windows": results,
        "summary": {
            "total": len(results),
            "intact": intact,
            "tampered": tampered,
            "missing": missing,
            "not_on_chain": not_on_chain,
        },
        "warning": error,
    })


@app.route("/api/recent-logs")
def api_recent_logs():
    """
    Returns the most recent lines in logs.txt as-is, newest last, with
    their real (1-indexed) line numbers â€” so the dashboard can show a
    live tail of the log file itself, not just window-level status.
    """
    import os

    if not os.path.exists(verification_core.LOG_FILE):
        return jsonify({"lines": []})

    with open(verification_core.LOG_FILE, "r") as f:
        all_lines = f.readlines()

    tail_count = 25
    start_index = max(0, len(all_lines) - tail_count)

    entries = []
    for i in range(start_index, len(all_lines)):
        raw = all_lines[i].rstrip("\n")
        parsed = None
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            pass
        entries.append({
            "line_number": i + 1,
            "raw": raw,
            "action": parsed.get("action") if parsed else None,
            "user_id": parsed.get("user_id") if parsed else None,
            "source_ip": parsed.get("source_ip") if parsed else None,
            "suspicious_score": parsed.get("suspicious_score", 0) if parsed else 0,
        })

    return jsonify({"lines": entries, "total_lines": len(all_lines)})


@app.route("/api/llm-status")
def api_llm_status():
    """Tells the dashboard whether the local Ollama model is reachable,
    so it can show a 'Local AI: Connected' or 'Offline' badge."""
    available = ollama_explainer.is_ollama_available()
    return jsonify({
        "available": available,
        "model": ollama_explainer.MODEL_NAME if available else None,
    })


@app.route("/api/simulate-attack", methods=["POST"])
def api_simulate_attack():
    """
    Live demo helper: picks the latest INTACT window and modifies one of
    its log lines, exactly like an attacker editing the log file would.
    This lets the dashboard trigger a real, visible tamper event with one
    click instead of manually editing logs.txt during a live demo.

    Log lines may be the newer JSON format (from ingest_server.py /
    log_generator.py) or the older plain-text format from earlier in the
    project â€” this handles both.
    """
    results, _ = verification_core.get_all_window_statuses()
    intact_windows = [r for r in results if r["status"] == "INTACT"]

    if not intact_windows:
        return jsonify({"success": False, "message": "No intact anchored window available to attack. Anchor some windows first."})

    target = intact_windows[-1]
    window_id = target["window_id"]

    with open(verification_core.CHAIN_FILE, "r") as f:
        chain = json.load(f)

    position = 0
    target_start = None
    target_count = None
    for entry in chain:
        if entry["window_id"] == window_id:
            target_start = position
            target_count = entry["num_lines"]
            break
        position += entry["num_lines"]

    if target_start is None:
        return jsonify({"success": False, "message": f"Could not locate window {window_id} in logs.txt."})

    with open(verification_core.LOG_FILE, "r") as f:
        lines = f.readlines()

    line_index = target_start + (target_count // 2)
    original = lines[line_index]

    tampered = None
    try:
        record = json.loads(original)
        original_action = record.get("action", "")
        record["action"] = f"{original_action}_FORGED_BY_ATTACKER"
        tampered = json.dumps(record) + "\n"
    except (json.JSONDecodeError, ValueError):
        # fall back for older plain-text log lines
        if "AUTH_SUCCESS" in original:
            tampered = original.replace("AUTH_SUCCESS", "AUTH_SUCCESS_FORGED_BY_ATTACKER")
        elif "AUTH_FAILURE" in original:
            tampered = original.replace("AUTH_FAILURE", "AUTH_SUCCESS")
        else:
            tampered = original.rstrip("\n") + " [TAMPERED]\n"

    lines[line_index] = tampered

    # log_generator.py keeps appending new lines to logs.txt in the
    # background, even while this request is running. If we blindly
    # overwrite the whole file with the snapshot we read above, any
    # lines appended in between get silently dropped â€” which breaks
    # every window's line count AFTER the tampered one, making them
    # all falsely show as TAMPERED too. So right before writing, check
    # whether the file has grown since our read, and if so, carry
    # those newer lines forward instead of discarding them.
    with open(verification_core.LOG_FILE, "r") as f:
        latest_lines = f.readlines()
    if len(latest_lines) > len(lines):
        lines = lines + latest_lines[len(lines):]

    with open(verification_core.LOG_FILE, "w") as f:
        f.writelines(lines)

    return jsonify({
        "success": True,
        "window_id": window_id,
        "original_line": original.strip(),
        "tampered_line": tampered.strip(),
        "message": f"Window {window_id} tampered. Refresh will show it flip to TAMPERED."
    })


@app.route("/twiml/alert")
def twiml_alert():
    """
    Returns a tiny TwiML response Twilio can fetch (via the "url" param
    on calls.create) to say a specific alert message out loud. Trial
    Twilio accounts reject inline TwiML passed directly in the API call,
    so this hosted-URL approach is what actually works on a trial account.

    Uses a clearer Amazon Polly voice (the plain default Twilio voice
    sounds robotic/unclear) and repeats the message three times with
    pauses so the call runs a solid 10+ seconds instead of hanging up
    almost immediately.
    """
    from flask import request, Response
    window_id = request.args.get("window_id", "unknown")
    status = request.args.get("status", "an issue")
    message = (
        f"Alert from Sentinel Vault. Your logs are being tampered with. "
        f"Log window {window_id} has flipped to {status}. "
        f"Please check your dashboard immediately."
    )
    say = f'<Say voice="Polly.Joanna" language="en-US">{message}</Say>'
    twiml = (
        '<?xml version="1.0" encoding="UTF-8"?><Response>'
        + say + '<Pause length="2"/>'
        + say + '<Pause length="2"/>'
        + say
        + '</Response>'
    )
    return Response(twiml, mimetype="text/xml")


@app.route("/api/simulate-missing", methods=["POST"])
def api_simulate_missing():
    """
    Live demo helper for the MISSING status: picks a window that is
    already anchored on-chain and INTACT, and deletes its entire record
    from hash_chain.json -- exactly like an attacker erasing a whole
    window's local evidence while its on-chain proof still exists.

    Only targets windows that have a stored "start_line" (written by the
    current hash_windows.py), since those windows' positions don't depend
    on summing the line counts of windows before them -- so removing one
    doesn't corrupt the position math for any other window. Older windows
    without "start_line" are skipped to avoid that cascade.
    """
    results, _ = verification_core.get_all_window_statuses()

    eligible = [
        r for r in results
        if r["status"] == "INTACT" and r.get("source") == "blockchain"
    ]

    if not eligible:
        return jsonify({
            "success": False,
            "message": "No anchored, intact window is eligible yet. Wait for a few more windows to be hashed and anchored, then try again."
        })

    with open(verification_core.CHAIN_FILE, "r") as f:
        chain = json.load(f)

    chain_by_id = {entry["window_id"]: entry for entry in chain}

    target = None
    for r in sorted(eligible, key=lambda r: -r["window_id"]):
        entry = chain_by_id.get(r["window_id"])
        if entry and "start_line" in entry:
            target = r
            break

    if target is None:
        return jsonify({
            "success": False,
            "message": "No eligible window has an explicit start position yet (only windows hashed after this feature was added qualify). Wait for a new window to be hashed and anchored, then try again."
        })

    window_id = target["window_id"]
    new_chain = [entry for entry in chain if entry["window_id"] != window_id]

    with open(verification_core.CHAIN_FILE, "w") as f:
        json.dump(new_chain, f, indent=2)

    return jsonify({
        "success": True,
        "window_id": window_id,
        "message": f"Window {window_id}'s local record deleted. Refresh will show it flip to MISSING (its on-chain proof still exists)."
    })


if __name__ == "__main__":
    # threaded=True: without this, one slow request (e.g. simulate-attack
    # waiting on a local AI explanation) blocks every other request -- the
    # whole dashboard freezes until it finishes, which looks like windows
    # have "disappeared" if you refresh mid-attack.
    app.run(debug=True, port=5000, threaded=True)

