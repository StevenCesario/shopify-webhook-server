import logging, time
import os, sys # sys for the new secret handling
from celery import Celery
from dotenv import load_dotenv

# --- Helper functions from utils.py ---
from utils import hash_data, send_to_meta_capi, CAPI_URL

# --- Environment Variable for Celery Broker ---
load_dotenv()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# --- Celery App Initialization ---
celery_app = Celery(
    'tasks',
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_track_started=True
)

# --- THE BACKGROUND TASK ---
@celery_app.task(name="process_shopify_webhook")
def process_shopify_webhook(webhook_data: dict):
    """
    This task runs in the background.
    It receives the Shopify order data, parses it, and sends it to Meta CAPI.
    """
    logging.info("Celery worker: Received Shopify webhook for processing.")

    try:
        # --- 1. Parse Shopify PII ---
        email = webhook_data.get('email')        
        billing_address = webhook_data.get('billing_address', {})
        shipping_address = webhook_data.get('shipping_address', {})
        
        # Using the same logic as the client side index.js
        phone = webhook_data.get('phone') or \
                billing_address.get('phone') or \
                shipping_address.get('phone')
        
        full_name = billing_address.get('name', '')
        first_name, last_name = (full_name.split(' ', 1) + [''])[:2] # Safe split
        city = billing_address.get('city')
        postal_code = billing_address.get('zip')
        country_code = billing_address.get('country_code') # e.g., "SE"

        # --- 2. Parse Purchase Value ---
        value = float(webhook_data.get('total_price', 0.0))
        currency = webhook_data.get('currency', 'SEK').upper()

        # --- 3. ⭐ NEW: Parse Browser & External ID data ---
        client_ip = webhook_data.get('browser_ip')
        client_details = webhook_data.get('client_details', {})
        client_user_agent = client_details.get('user_agent')
        order_id_str = str(webhook_data.get('id', '')) # Use order ID as external_id

        logging.info(
            "Celery worker: Extracted PII: email=%s, name=%s, ip=%s, ua=%s",
            bool(email), bool(full_name), bool(client_ip), bool(client_user_agent)
        )

        # --- 4. Build the CAPI Payload (reusing hash_data function) ---
        user_data = {
            "em": hash_data(email or ""),
            "fn": hash_data(first_name or ""),
            "ln": hash_data(last_name or ""),
            "ph": hash_data(phone or ""),
            "ct": hash_data(city or ""),
            "zp": hash_data(postal_code or ""),
            "country": hash_data(country_code or ""),

            # ⭐ NEW: Add browser/external data (modeled on your main.py)
            "client_ip_address": (client_ip or None),
            "client_user_agent": (client_user_agent or None),
            "external_id": hash_data(order_id_str), # Hashed Shopify Order ID
        }
        # Remove any empty fields
        user_data = {k: v for k, v in user_data.items() if v}

        custom_data = {
            "currency": currency,
            "value": value
        }

        event_id = f"shopify_{order_id_str}" # Use for deduplication

        meta_purchase_event = {
            "event_name": "Purchase",
            "event_time": int(time.time()),
            "action_source": "website", # From Shopify, but triggered by website action
            "user_data": user_data,
            "custom_data": custom_data,
            "event_id": event_id
        }

        # --- 5. Send to Meta CAPI (reusing send_to_meta_capi function) ---
        logging.info("Celery worker: Sending processed event to Meta CAPI.")
        send_to_meta_capi(meta_purchase_event)

        logging.info("Celery worker: Successfully processed and sent Shopify event.")
        return {"status": "success", "event_id": meta_purchase_event["event_id"]}
    
    except Exception as e:
        logging.error(f"Celery worker: Failed to process Shopify webhook: {str(e)}", exc_info=True)
        # Celery can be configured to retry this task
        raise e