import logging
import hashlib
import requests, json
import os, sys
from capi_param_builder import ParamBuilder
from dotenv import load_dotenv

# --- Environment Variables ---
load_dotenv()
FB_PIXEL_ID = os.getenv("FB_PIXEL_ID", "YOUR_PIXEL_ID")
try:
    FB_ACCESS_TOKEN = os.environ["FB_ACCESS_TOKEN"]
except KeyError:
    logging.critical("FATAL ERROR: FB_ACCESS_TOKEN environment variable not set.")
    sys.exit(1) # Crash the program

CAPI_URL = f"https://graph.facebook.com/v24.0/{FB_PIXEL_ID}/events?access_token={FB_ACCESS_TOKEN}"

# --- NEW: Meta Parameter Builder ---
# We instantiate the builder here to be shared by main.py and celery_worker.py
# Using "myshopify.com" as the eTLD+1 for our stores.
# For cookies only. Meta are absolute nut jobs, writing about getNormalizedAndHashedPII when it doesn't exist
paramBuilder = ParamBuilder(["myshopify.com"])

# --- Helper Functions ---
def hash_data(value: str) -> str: # Would be replaced by getNormalizedAndHashedPII *if it existed*
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