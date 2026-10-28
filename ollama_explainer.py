"""
Local LLM incident explainer.

When verification flags a window as TAMPERED or MISSING, this module asks
a locally-running Ollama model to turn that result into a short,
human-readable incident summary for the dashboard.

Important: this NEVER decides whether something is tampered. That decision
is already made deterministically by hash comparison in verification_core.py,
before this module is even called. This only explains an already-confirmed
result, and it never leaves the local machine (no external API calls).

If Ollama isn't running, everything still works — a simple templated
explanation is used instead, and the dashboard shows "Local AI: Offline".
"""
import json
import urllib.request
import urllib.error

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL_NAME = "qwen2.5:3b"


def is_ollama_available():
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _line_detail_text(window):
    tampered_lines = window.get("tampered_lines")
    if not tampered_lines:
        return ""
    line_numbers = [str(t["line_number"]) for t in tampered_lines if t.get("line_number") is not None]
    if line_numbers:
        return f" The exact affected line number(s): {', '.join(line_numbers)}."
    return ""


def _fallback_explanation(window):
    status = window["status"]
    wid = window["window_id"]

    if status == "TAMPERED":
        return (
            f"Window {wid} failed verification: the hash recomputed from the current "
            f"logs no longer matches the hash anchored on-chain. This means at least "
            f"one log line in this window was modified or deleted after it was anchored."
            f"{_line_detail_text(window)}"
        )
    if status == "MISSING":
        return (
            f"Window {wid} has a hash anchored on the blockchain, but its log data no "
            f"longer exists locally. This points to an entire window being deleted, "
            f"an attempt to erase evidence rather than just edit it."
        )
    return None


def explain_window(window):
    """
    window: one row dict from verification_core.get_all_window_statuses(),
    with at least "window_id", "status", "num_lines", "onchain_hash",
    "recomputed_hash".

    Returns a short text explanation, or None for INTACT / NOT_ON_CHAIN
    windows (nothing to explain there).
    """
    if window["status"] not in ("TAMPERED", "MISSING"):
        return None

    if not is_ollama_available():
        return _fallback_explanation(window)

    tampered_lines = window.get("tampered_lines") or []
    line_numbers = [str(t["line_number"]) for t in tampered_lines if t.get("line_number") is not None]
    line_info = f"Exact tampered line number(s): {', '.join(line_numbers)}\n" if line_numbers else ""

    prompt = (
        "You are a security analyst assistant. Write ONE short paragraph (2-3 sentences, "
        "plain language, no markdown) explaining this log integrity discrepancy to someone "
        "reading a dashboard. Be factual, do not speculate beyond what is given. If an exact "
        "line number is given below, mention it directly.\n\n"
        f"Window ID: {window['window_id']}\n"
        f"Status: {window['status']}\n"
        f"Line count: {window.get('num_lines', 'unknown')}\n"
        f"On-chain hash: {window.get('onchain_hash') or 'not available'}\n"
        f"Recomputed hash: {window.get('recomputed_hash') or 'not available'}\n"
        f"{line_info}"
    )

    try:
        payload = json.dumps({
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data.get("response", "").strip()
            return text if text else _fallback_explanation(window)
    except Exception:
        return _fallback_explanation(window)
