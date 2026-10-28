"""
Sentinel Vault — incident alerting.

Fires a push notification (always, free, no account needed) and a real
phone call (if Twilio is configured) the moment a NEW tampered/missing
window is first detected -- so the person running this gets woken up
even if the attack happens at 3am and nobody is looking at the dashboard.

Push notifications: uses ntfy.sh, a free public push service. No signup,
no API key -- you just pick a topic name (make it hard to guess, since
anyone who knows your topic name can also see/send to it) and install
the ntfy app on your phone, subscribed to that same topic.

Phone calls: uses Twilio (https://www.twilio.com). This needs a Twilio
account you create yourself -- fill in the four values below once you
have them. Until they're filled in, phone calls are simply skipped (push
notifications still work on their own).
"""
import json
import os
import urllib.request

def _load_twilio_secrets():
    """Reads Twilio credentials from twilio_secrets.json if present
    (gitignored, lives next to this file) as a local-dev fallback."""
    secrets = {}
    secrets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "twilio_secrets.json")
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path) as f:
                secrets = json.load(f)
        except Exception:
            secrets = {}
    return secrets


_twilio_secrets = _load_twilio_secrets()

# Read configurations: Environment variables take priority over local twilio_secrets.json
NTFY_TOPIC = os.environ.get("NTFY_TOPIC") or _twilio_secrets.get("NTFY_TOPIC", "sentinel-vault-vaibhav-5c603c7cc1")
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID") or _twilio_secrets.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN") or _twilio_secrets.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER") or _twilio_secrets.get("TWILIO_FROM_NUMBER", "")
TWILIO_TO_NUMBER = os.environ.get("TWILIO_TO_NUMBER") or _twilio_secrets.get("TWILIO_TO_NUMBER", "")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL") or _twilio_secrets.get("PUBLIC_BASE_URL", "")


def send_push_notification(window_id, status):
    """Best-effort -- never raises, so a notification failure can't break
    the dashboard."""
    topic = os.environ.get("NTFY_TOPIC") or NTFY_TOPIC
    if not topic or "change-me" in topic:
        return
    try:
        title = f"Sentinel Vault: Window {window_id} {status}"
        body = f"Log window {window_id} just flipped to {status}. Check the dashboard."
        req = urllib.request.Request(
            f"https://ntfy.sh/{topic}",
            data=body.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": "urgent",
                "Tags": "rotating_light",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[notify] push notification failed: {e}")


def send_phone_call(window_id, status):
    """Best-effort -- never raises. Skips silently if Twilio or the
    public tunnel URL isn't configured."""
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID") or TWILIO_ACCOUNT_SID
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN") or TWILIO_AUTH_TOKEN
    from_number = os.environ.get("TWILIO_FROM_NUMBER") or TWILIO_FROM_NUMBER
    to_number = os.environ.get("TWILIO_TO_NUMBER") or TWILIO_TO_NUMBER
    public_url = os.environ.get("PUBLIC_BASE_URL") or PUBLIC_BASE_URL

    if not (account_sid and auth_token and from_number and to_number):
        return
    if not public_url:
        print("[notify] phone call skipped: PUBLIC_BASE_URL not set in environment or twilio_secrets.json")
        return
    try:
        from twilio.rest import Client
        client = Client(account_sid, auth_token)
        twiml_url = f"{public_url.rstrip('/')}/twiml/alert?window_id={window_id}&status={status}"
        client.calls.create(
            to=to_number,
            from_=from_number,
            url=twiml_url,
        )
    except Exception as e:
        print(f"[notify] phone call failed: {e}")


def alert_new_incident(window_id, status):
    """Call this for a window the FIRST time it's seen as TAMPERED/MISSING
    (the caller is responsible for not calling this repeatedly for the
    same window -- see dashboard_app.py)."""
    print(f"[notify] ALERTING for window {window_id} ({status})")
    send_push_notification(window_id, status)
    send_phone_call(window_id, status)
