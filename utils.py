import logging
import hashlib
import requests, json
import os, sys
from typing import Optional, Any
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
paramBuilder = ParamBuilder(["myshopify.com"])

# --- Helper Functions ---
def hash_data(value: str) -> str: 
    """Hashes a string value using SHA-256 for Meta CAPI."""
    if not value:
        return ""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()

def send_to_meta_capi(event_data: dict, test_code: Optional[str] = None):
    """
    Constructs the final payload and sends a single event to the Meta Conversions API.
    
    Args:
        event_data (dict): The event object (containing event_name, user_data, etc.)
        test_code (str, optional): The test_event_code for debugging in Events Manager.
    """
    # Fix: Explicitly type hint the dict so Pylance knows it can hold mixed types
    meta_payload: dict[str, Any] = {"data": [event_data]}
    
    # Add test_event_code to the ROOT level if provided
    if test_code:
        meta_payload["test_event_code"] = test_code

    logging.info("Sending payload to Meta CAPI: %s", json.dumps(meta_payload, indent=2))

    # # --- DEV MODE START: Prevent actual sending ---
    # logging.info("🚫 DRY RUN: Would have been successfully sent to Meta!")
    
    # # Return a fake success response so main.py doesn't crash
    # return {"id": "MOCK_EVENT_ID_12345", "status": "mock_success"}

    try:
        response = requests.post(CAPI_URL, json=meta_payload)
        response.raise_for_status()
        logging.info("Meta CAPI Success Response: %s", response.json())
        return response.json()
    except requests.exceptions.RequestException as e:
        # Construct a detailed error message including the response body if available
        error_msg = f"Meta CAPI request failed: {str(e)}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                # Append the JSON error from Meta (e.g., "Unexpected key")
                error_msg += f" - Response: {e.response.text}"
            except Exception:
                pass
        
        logging.error(error_msg)
        # Raise a ConnectionError so the caller knows it failed
        raise ConnectionError(error_msg)