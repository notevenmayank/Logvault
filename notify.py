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

# ---- Push notification (ntfy.sh) ----
# Pick your own topic name here -- anything unique. Then install the ntfy
# app (Android/iOS/web: https://ntfy.sh/app) and subscribe to this exact
# topic name to get the alert on your phone.
NTFY_TOPIC = "sentinel-vault-vaibhav-5c603c7cc1"

# ---- Phone call (Twilio) ----
# Fill these in after creating a free Twilio trial account:
#   1. Sign up at https://www.twilio.com/try-twilio
#   2. From the console dashboard, copy your Account SID and Auth Token
#   3. Get a free Twilio phone number (Phone Numbers -> Buy a number)
#   4. On a trial account you can only call a number YOU verified in the
#      console (Phone Numbers -> Verified Caller IDs) -- verify your own
#      phone there first.
def _load_twilio_secrets():
    """Reads Twilio credentials from twilio_secrets.json if present
    (gitignored, lives next to this file), falling back to environment
    variables. Local file is just easier to edit by hand than setting
    env vars every time you open a new terminal."""
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

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID") or _twilio_secrets.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN") or _twilio_secrets.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER") or _twilio_secrets.get("TWILIO_FROM_NUMBER", "")   # the Twilio number you were given, e.g. +1415XXXXXXX
TWILIO_TO_NUMBER = os.environ.get("TWILIO_TO_NUMBER") or _twilio_secrets.get("TWILIO_TO_NUMBER", "")       # YOUR phone, e.g. +9198XXXXXXXX

# Trial Twilio accounts reject inline TwiML (the "twiml" param) on
# calls.create -- "Invalid or disallowed parameters provided". The fix
# that actually works on trial is to pass "url" pointing at a page that
# RETURNS TwiML, which Twilio's servers fetch over the public internet.
# dashboard_app.py exposes exactly that at /twiml/alert, but it's only
# reachable at localhost:5000, so Twilio can't fetch it directly -- this
# needs a public tunnel (e.g. `npx localtunnel --port 5000`) pointed at
# it. Put that tunnel's https URL here (no trailing slash).
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL") or _twilio_secrets.get("PUBLIC_BASE_URL", "")


def send_push_notification(window_id, status):
    """Best-effort -- never raises, so a notification failure can't break
    the dashboard."""
    if not NTFY_TOPIC or "change-me" in NTFY_TOPIC:
        return
    try:
        title = f"Sentinel Vault: Window {window_id} {status}"
        body = f"Log window {window_id} just flipped to {status}. Check the dashboard."
        req = urllib.request.Request(
            f"https://ntfy.sh/{NTFY_TOPIC}",
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
    public tunnel URL isn't configured yet."""
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER and TWILIO_TO_NUMBER):
        return
    if not PUBLIC_BASE_URL:
        print("[notify] phone call skipped: PUBLIC_BASE_URL not set in twilio_secrets.json (run a tunnel, e.g. `npx localtunnel --port 5000`, and put its https URL there)")
        return
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        twiml_url = f"{PUBLIC_BASE_URL}/twiml/alert?window_id={window_id}&status={status}"
        client.calls.create(
            to=TWILIO_TO_NUMBER,
            from_=TWILIO_FROM_NUMBER,
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
