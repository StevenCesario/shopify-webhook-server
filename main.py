import logging
import json, ipaddress
import hashlib, hmac, base64
import os, sys
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Header, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError
from dotenv import load_dotenv

# Helper functions from utils.py
from utils import hash_data, send_to_meta_capi, paramBuilder

# NEW: Celery worker!
from celery_worker import celery_app

# --- Basic Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# --- Environment Variables ---
load_dotenv()
try:
    SHOPIFY_CLIENT_SECRET = os.environ["SHOPIFY_CLIENT_SECRET"]
except KeyError:
    logging.critical("FATAL ERROR: SHOPIFY_CLIENT_SECRET environment variable not set.")
    sys.exit(1) # Crash the program

# --- Allowed Origins for CORS ---
shopify_page_domain = "https://schemin-babys-store.myshopify.com/"
dev_store_domain = "https://test-dev-store-645645701.myshopify.com"

# --- Regex for validation ---
# FBP_REGEX = re.compile(r'^fb\.1\.\d+\.\d+$') # (REMOVED, SDK handles this)

# --- FastAPI App Initialization ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        shopify_page_domain,
        dev_store_domain
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---
class ClientPayload(BaseModel):
    event_name: str
    event_time: int
    event_id: Optional[str] = None # Essential for deduplication
    event_source_url: Optional[str] = None
    action_source: str
    user_data: dict
    custom_data: Optional[dict] = None

# --- Helper Functions ---
# New helper function for HMAC Validation
def verify_shopify_hmac(secret: str, body: bytes, hmac_header: str) -> bool:
    """
    Validates the Shopify HMAC signature.
    """
    if not hmac_header:
        logging.warning("HMAC validation failed: No hmac_header provided.")
        return False
    if not secret:
        logging.error("HMAC validation failed: SHOPIFY_CLIENT_SECRET is not set.")
        return False
    
    try:
        # 1. Create a new HMAC digest using the secret and the raw body
        hash_digest = hmac.new(
            secret.encode('utf-8'),
            body,
            hashlib.sha256
        ).digest()
        
        # 2. Base64-encode the digest
        computed_hmac_b64 = base64.b64encode(hash_digest)
        
        # 3. Compare securely (prevents timing attacks)
        return hmac.compare_digest(
            computed_hmac_b64,
            hmac_header.encode('utf-8')
        )
    except Exception as e:
        logging.error(f"HMAC validation error: {e}")
        return False

# hash_data and send_to_meta_capi helper functions moved to utils.py to prevent circular imports


# --- API Endpoints ---

@app.post("/process-event")
async def process_event(request: Request, response: Response): # Changed: now only takes the raw request # Updated: and Response!
    """Handles client-side browser events (PII-poor, browser-rich)."""
    
    # -- New debugging block ---
    raw_payload = {}
    try:
        raw_payload = await request.json()
        logging.info("RAW client-side payload RECEIVED: %s", raw_payload)
    except Exception as e:
        logging.error("Failed to parse raw JSON from pixel: %s", e)
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")
    
    # --- Manual Pydantic Validation ---
    try:
        payload = ClientPayload(**raw_payload)
    except ValidationError as e:
        logging.warning("Pydantic validation FAILED for raw payload: %s", e)
        # We could still try to proceed, but it's safer to fail
        # This will tell us if the pixel is sending a *completely* wrong structure
        raise HTTPException(status_code=422, detail=f"Invalid payload structure: {e}")

    logging.info("Received Pydantic-validated client-side event payload: %s", payload.model_dump())

    # --- NEW: Use Meta Parameter Builder ---
    domain = request.headers.get("host", "")
    cookie_dict = dict(request.cookies)
    referral_link = request.headers.get("referer")

    query_params_list_dict = {}
    for key in request.query_params:
        query_params_list_dict[key] = request.query_params.getlist(key)

    # Process the request to generate/update cookies and get IP
    updated_cookies = paramBuilder.process_request(
        domain,
        query_params_list_dict,
        cookie_dict,
        referral_link,
    )

    # Set the recommended cookies on the response
    for cookie in updated_cookies:
        response.set_cookie(
            key=cookie.name,
            value=cookie.value,
            max_age=cookie.max_age,
            domain=cookie.domain,
            path="/"
        )
    
    # Get values from the SDK (its main job)
    sdk_fbc = paramBuilder.get_fbc()
    sdk_fbp = paramBuilder.get_fbp()

    # Get values from the pixel payload (our fallback)
    pixel_fbc = payload.user_data.get("fbc", "")
    pixel_fbp = payload.user_data.get("fbp", "")

    # Prioritize the SDK's value, but fall back to the pixel's value
    fbc_val = sdk_fbc if sdk_fbc else pixel_fbc
    fbp_val = sdk_fbp if sdk_fbp else pixel_fbp

    logging.info("SDK-extracted cookies: fbc: %s, fbp: %s", sdk_fbc, sdk_fbp)
    logging.info("Pixel-provided cookies: fbc: %s, fbp: %s", pixel_fbc, pixel_fbp)
    logging.info("FINAL fbc: %s, fbp: %s", fbc_val, fbp_val)

    # Get IP and User-Agent manually
    x_forwarded_for = request.headers.get("x-forwarded-for", "")
    client_ip = x_forwarded_for.split(",")[0].strip() if x_forwarded_for else (request.client.host if request.client else "")
    try:
        if client_ip: ipaddress.ip_address(client_ip)
    except ValueError:
        client_ip = "" # Nullify
    
    client_user_agent = payload.user_data.get("user_agent", "") or request.headers.get("user-agent", "")
    
    logging.info("SDK-extracted cookies: fbc: %s, fbp: %s", fbc_val, fbp_val)
    logging.info("Manually-extracted IP: %s, User-Agent: %s", client_ip, client_user_agent)

    # HASH PII using our v1.0 hash_data (SDK hashing doesn't exist)
    hashed_email = hash_data(payload.user_data.get("em", ""))
    hashed_first_name = hash_data(payload.user_data.get("fn", ""))
    hashed_last_name = hash_data(payload.user_data.get("ln", ""))
    hashed_phone = hash_data(payload.user_data.get("ph", ""))
    hashed_country = hash_data(payload.user_data.get("country", ""))
    hashed_city = hash_data(payload.user_data.get("ct", ""))
    hashed_zip = hash_data(payload.user_data.get("zp", ""))
    hashed_external_id = hash_data(payload.user_data.get("external_id", ""))

    # Cleaning custom_data
    final_cleaned_custom_data = {}
    if payload.custom_data:
        # ... logic for cleaning custom_data as before ...
        final_cleaned_custom_data = {k: v for k, v in payload.custom_data.items() if v is not None and not (isinstance(v, str) and v.lower() == 'null')}
        if "value" in final_cleaned_custom_data:
            try:
                final_cleaned_custom_data["value"] = float(final_cleaned_custom_data["value"])
            except (ValueError, TypeError):
                final_cleaned_custom_data["value"] = 0.0
        if "currency" not in final_cleaned_custom_data or not final_cleaned_custom_data["currency"]:
            final_cleaned_custom_data["currency"] = "SEK"
            
    # Building final Meta CAPI payload
    meta_payload_user_data = {
        "client_ip_address": client_ip,
        "client_user_agent": client_user_agent,
        "fbc": fbc_val,
        "fbp": fbp_val,
        "em": hashed_email,
        "fn": hashed_first_name,
        "ln": hashed_last_name,
        "ph": hashed_phone,
        "country": hashed_country,
        "ct": hashed_city,
        "zp": hashed_zip,
        "external_id": hashed_external_id
    }
    meta_payload_user_data = {k: v for k, v in meta_payload_user_data.items() if v}

    meta_payload_event_data = {
        "event_name": payload.event_name,
        "event_time": payload.event_time,
        "action_source": payload.action_source,
        "user_data": meta_payload_user_data,
        "custom_data": final_cleaned_custom_data
    }
    if payload.event_source_url:
        meta_payload_event_data["event_source_url"] = payload.event_source_url
    if payload.event_id:
        meta_payload_event_data["event_id"] = payload.event_id

    try:
        meta_response = send_to_meta_capi(meta_payload_event_data)
        return {"status": "success", "meta_response": meta_response}
    except ConnectionError as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/shopify-webhook")
async def shopify_webhook(request: Request, x_shopify_hmac_sha256: str = Header(None)):
    """
    Handles server-side Shopify webhooks (e.g., orders/create).
    
    1. Verifies HMAC signature.
    2. If valid, passes the raw body to a Celery queue for background processing.
    3. Immediately returns 200 OK to Shopify.
    """
    
    # 1. Get the raw request body (CRITICAL for HMAC)
    payload_body = await request.body()

    # 2. (Security First 🔐) Verify the HMAC signature
    is_valid = verify_shopify_hmac(
        secret=SHOPIFY_CLIENT_SECRET,
        body=payload_body,
        hmac_header=x_shopify_hmac_sha256
    )

    if not is_valid:
        logging.error("Shopify Webhook: HMAC validation failed.")
        raise HTTPException(
            status_code=401, 
            detail="HMAC validation failed. Request is not from Shopify."
        )

    logging.info("Shopify Webhook: HMAC validation successful.")

    # 3. Parse body to JSON *after* validation
    try:
        webhook_data = json.loads(payload_body)
    except json.JSONDecodeError:
        logging.error("Shopify Webhook: Failed to decode JSON body.")
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    # 4. (Queue It!) Now using the clean way
    try:
        # Using the Pylance-friendly way to call a task by its name
        celery_app.send_task(
            "process_shopify_webhook",  # The 'name' defined in the @celery_app.task decorator
             args=[webhook_data]        # The arguments for the function
        )
        logging.info("Shopify Webhook: Task successfully queued for processing.")
    except Exception as e:
        # This could happen if Redis is down
        logging.critical(f"Shopify Webhook: FAILED TO QUEUE TASK: {e}")
        # We must return 500 so Shopify retries
        raise HTTPException(status_code=500, detail="Failed to queue task.")

    # 5. (Fast Response!) Acknowledge receipt to Shopify immediately
    return {"status": "success", "message": "Webhook received and queued."}