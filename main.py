import logging
import json, ipaddress
import hashlib, hmac, base64
import os, sys
from typing import Optional, List, Union

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
shopify_page_domain = "https://wearhelios.com/"
dev_store_domain = "https://helios-dev-store.myshopify.com/"

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
    event_id: Optional[str] = None
    event_source_url: Optional[str] = None
    action_source: str
    user_data: dict
    custom_data: Optional[dict] = None

# NEW: Model for Meta's Batch/Test format
class MetaTestPayload(BaseModel):
    data: List[ClientPayload]
    test_event_code: Optional[str] = None

# --- Helper Functions ---
def verify_shopify_hmac(secret: str, body: bytes, hmac_header: str) -> bool:
    """Validates the Shopify HMAC signature."""
    if not hmac_header:
        logging.warning("HMAC validation failed: No hmac_header provided.")
        return False
    if not secret:
        logging.error("HMAC validation failed: SHOPIFY_CLIENT_SECRET is not set.")
        return False
    
    try:
        hash_digest = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).digest()
        computed_hmac_b64 = base64.b64encode(hash_digest)
        # # --- DEBUGGING START (Remove after fixing) ---
        # logging.info(f"🔍 DEBUG: Secret being used: {secret[:5]}...{secret[-5:]} (Length: {len(secret)})")
        # logging.info(f"🔍 DEBUG: Received Body Length: {len(body)}")
        # logging.info(f"🔍 DEBUG: Shopify Sent HMAC:   {hmac_header}")
        # logging.info(f"🔍 DEBUG: Calculated HMAC:     {computed_hmac_b64}")
        # # --- DEBUGGING END ---
        return hmac.compare_digest(computed_hmac_b64, hmac_header.encode('utf-8'))
    except Exception as e:
        logging.error(f"HMAC validation error: {e}")
        return False

async def _process_single_event_logic(
    payload: ClientPayload, 
    request: Request, 
    response: Response, 
    test_event_code: Optional[str] = None
):
    """
    Internal helper to process a single event payload. 
    Handles cookie extraction, hashing, and sending to CAPI.
    """
    
    # --- 1. Parameter Builder & Cookie Logic ---
    # Note: If this is a server-to-server test call, these might be empty, which is fine.
    domain = request.headers.get("host", "")
    cookie_dict = dict(request.cookies)
    referral_link = request.headers.get("referer")

    query_params_list_dict = {}
    for key in request.query_params:
        query_params_list_dict[key] = request.query_params.getlist(key)

    updated_cookies = paramBuilder.process_request(
        domain, query_params_list_dict, cookie_dict, referral_link
    )

    # Set cookies on response (useful for real browser traffic, harmless for test traffic)
    for cookie in updated_cookies:
        response.set_cookie(
            key=cookie.name,
            value=cookie.value,
            max_age=cookie.max_age,
            domain=cookie.domain,
            path="/"
        )
    
    # --- 2. Extract FBC/FBP ---
    sdk_fbc = paramBuilder.get_fbc()
    sdk_fbp = paramBuilder.get_fbp()
    pixel_fbc = payload.user_data.get("fbc", "")
    pixel_fbp = payload.user_data.get("fbp", "")

    fbc_val = sdk_fbc if sdk_fbc else pixel_fbc
    fbp_val = sdk_fbp if sdk_fbp else pixel_fbp

    # --- 3. IP and User Agent ---
    # Prioritize what is in the payload (common in test events), fallback to request headers
    payload_ip = payload.user_data.get("client_ip_address", "")
    payload_ua = payload.user_data.get("client_user_agent", "")

    # If not in payload, extract from Request headers
    if not payload_ip:
        x_forwarded_for = request.headers.get("x-forwarded-for", "")
        payload_ip = x_forwarded_for.split(",")[0].strip() if x_forwarded_for else (request.client.host if request.client else "")
    
    # Validate IP
    try:
        if payload_ip: ipaddress.ip_address(payload_ip)
    except ValueError:
        payload_ip = ""

    client_user_agent = payload_ua or request.headers.get("user-agent", "")

    # --- 4. Hashing PII ---
    hashed_email = hash_data(payload.user_data.get("em", ""))
    hashed_first_name = hash_data(payload.user_data.get("fn", ""))
    hashed_last_name = hash_data(payload.user_data.get("ln", ""))
    hashed_phone = hash_data(payload.user_data.get("ph", ""))
    hashed_country = hash_data(payload.user_data.get("country", ""))
    hashed_city = hash_data(payload.user_data.get("ct", ""))
    hashed_zip = hash_data(payload.user_data.get("zp", ""))
    hashed_external_id = hash_data(payload.user_data.get("external_id", ""))

    # --- 5. Clean Custom Data ---
    final_cleaned_custom_data = {}
    if payload.custom_data:
        final_cleaned_custom_data = {k: v for k, v in payload.custom_data.items() if v is not None and not (isinstance(v, str) and v.lower() == 'null')}
        if "value" in final_cleaned_custom_data:
            try:
                final_cleaned_custom_data["value"] = float(final_cleaned_custom_data["value"])
            except (ValueError, TypeError):
                final_cleaned_custom_data["value"] = 0.0
        if "currency" not in final_cleaned_custom_data or not final_cleaned_custom_data["currency"]:
            final_cleaned_custom_data["currency"] = "SEK"

    # --- 6. Build Meta Payload ---
    meta_payload_user_data = {
        "client_ip_address": payload_ip,
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
    # Remove empty keys
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
    
    # --- 7. Send to Meta ---
    # We don't add test_event_code to meta_payload_event_data here. Pass the test_code as a separate argument
    return send_to_meta_capi(meta_payload_event_data, test_code=test_event_code)


# --- API Endpoints ---

@app.get("/healthz")
async def healthz():
    """
    Standard Cloud-Native Health Check.
    Checks connectivity to Redis and the status of the Celery Worker.
    """
    health_report = {
        "status": "healthy",
        "components": {
            "api": "online",
            "redis": "unknown",
            "worker": "unknown"
        }
    }

    # 1. Check Redis Connection
    try:
        # We check if we can successfully ping the Redis broker
        celery_app.connection().ensure_connection()
        health_report["components"]["redis"] = "online"
    except Exception as e:
        health_report["status"] = "unhealthy"
        health_report["components"]["redis"] = f"offline: {str(e)}"

    # 2. Check Celery Worker Presence
    try:
        inspector = celery_app.control.inspect()
        # Returns a dict of active workers
        active = inspector.active()
        if active:
            health_report["components"]["worker"] = "online"
        else:
            health_report["status"] = "unhealthy"
            health_report["components"]["worker"] = "offline (no active workers found)"
    except Exception as e:
        health_report["status"] = "unhealthy"
        health_report["components"]["worker"] = f"error: {str(e)}"

    if health_report["status"] != "healthy":
        # Returns a 503 so Render/Postman knows immediately there is an issue
        raise HTTPException(status_code=503, detail=health_report)

    return health_report

@app.post("/process-event")
async def process_event(request: Request, response: Response):
    """
    Handles client-side browser events.
    Supports both single 'ClientPayload' and batched/test 'MetaTestPayload'.
    """
    
    # 1. Parse Raw JSON
    raw_payload = {}
    try:
        raw_payload = await request.json()
    except Exception as e:
        logging.error("Failed to parse raw JSON: %s", e)
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    # 2. Determine Payload Type (Batch vs Single)
    events_to_process = []
    test_code = None

    # Check if this matches the "MetaTestPayload" structure (has 'data' list)
    if "data" in raw_payload and isinstance(raw_payload["data"], list):
        logging.info("Received BATCH/TEST payload structure.")
        try:
            batch_data = MetaTestPayload(**raw_payload)
            events_to_process = batch_data.data
            test_code = batch_data.test_event_code
            logging.info(f"Processing batch of {len(events_to_process)} events. Test Code: {test_code}")
        except ValidationError as e:
            logging.error("Validation failed for Batch Payload: %s", e)
            raise HTTPException(status_code=422, detail=f"Invalid Batch structure: {e}")
    else:
        # Assume it's a single "ClientPayload"
        logging.info("Received SINGLE event payload structure.")
        try:
            single_data = ClientPayload(**raw_payload)
            events_to_process = [single_data]
            # No test code for standard single events usually, unless passed somehow else
        except ValidationError as e:
            logging.error("Validation failed for Single Payload: %s", e)
            raise HTTPException(status_code=422, detail=f"Invalid Payload structure: {e}")

    # 3. Process All Events
    results = []
    for event in events_to_process:
        try:
            # We await the helper function for each event
            # Note: In high-volume production, you might use asyncio.gather to do this in parallel
            res = await _process_single_event_logic(event, request, response, test_code)
            results.append(res)
        except ConnectionError as e:
            logging.error(f"Connection error sending to Meta: {e}")
            # We don't crash the whole batch for one failure, but we log it
            results.append({"error": str(e)})

    return {"status": "success", "processed_count": len(results), "meta_responses": results}


@app.post("/shopify-webhook")
async def shopify_webhook(request: Request, x_shopify_hmac_sha256: str = Header(None)):
    """
    Handles server-side Shopify webhooks.
    """
    payload_body = await request.body()

    # --- 1. DEV MODE: Force Validation to True ---
    is_valid = verify_shopify_hmac(
        secret=SHOPIFY_CLIENT_SECRET,
        body=payload_body,
        hmac_header=x_shopify_hmac_sha256
    )

    # logging.warning("⚠️ SECURITY WARNING: HMAC Validation is temporarily DISABLED for testing!")

    # --- 2. Comment out the failure check ---
    if not is_valid:
        logging.error("Shopify Webhook: HMAC validation failed.")
        raise HTTPException(status_code=401, detail="HMAC validation failed.")

    logging.info("Shopify Webhook: HMAC validation successful.")

    # logging.info("Shopify Webhook: HMAC validation SKIPPED (Dev Mode).")

    try:
        webhook_data = json.loads(payload_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    try:
        # logging.info(f"🔍 DEBUG: Current Broker URL is: {celery_app.conf.broker_url}")
        celery_app.send_task("process_shopify_webhook", args=[webhook_data])
        logging.info("Shopify Webhook: Task queued.")
    except Exception as e:
        logging.critical(f"Shopify Webhook: FAILED TO QUEUE TASK: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue task.")

    return {"status": "success", "message": "Webhook received and queued."}