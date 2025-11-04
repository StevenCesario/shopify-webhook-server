import logging
import hashlib
import json
import requests
import os
from dotenv import load_dotenv

# --- Environment Variables ---
load_dotenv()
FB_PIXEL_ID = os.getenv("FB_PIXEL_ID", "YOUR_PIXEL_ID")
FB_ACCESS_TOKEN = os.getenv("FB_ACCESS_TOKEN", "YOUR_ACCESS_TOKEN")
CAPI_URL = f"https://graph.facebook.com/v24.0/{FB_PIXEL_ID}/events?access_token={FB_ACCESS_TOKEN}"

# --- Helper Functions ---
def hash_data(value: str) -> str:
    """Hashes a string value using SHA-256 for Meta CAPI."""
    if not value:
        return ""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()

def send_to_meta_capi(event_data: dict):
    """
    Constructs the final payload and sends a single event to the Meta Conversions API.
    """
    meta_payload = {"data": [event_data]}
    logging.info("Sending payload to Meta CAPI: %s", json.dumps(meta_payload, indent=2))

    try:
        response = requests.post(CAPI_URL, json=meta_payload)
        response.raise_for_status()
        logging.info("Meta CAPI Success Response: %s", response.json())
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error("Meta CAPI request failed: %s", str(e))
        error_detail = f"Meta CAPI request failed: {str(e)}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail += f" - Response: {e.response.text}"
            except Exception:
                pass
        raise ConnectionError(error_detail)