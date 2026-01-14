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
        # Safe extraction: .get() returns None by default, which is fine for our hash_data function
        email = webhook_data.get('email')        
        
        # Handle cases where addresses might be None
        billing_address = webhook_data.get('billing_address') or {}
        shipping_address = webhook_data.get('shipping_address') or {}
        
        phone = webhook_data.get('phone') or \
                billing_address.get('phone') or \
                shipping_address.get('phone')
        
        full_name = billing_address.get('name', '')
        # Safe split even if name is empty
        parts = full_name.split(' ', 1) if full_name else []
        first_name = parts[0] if len(parts) > 0 else ''
        last_name = parts[1] if len(parts) > 1 else ''
        
        city = billing_address.get('city')
        postal_code = billing_address.get('zip')
        country_code = billing_address.get('country_code') 

        # --- 2. Parse Purchase Value ---
        try:
            value = float(webhook_data.get('total_price', 0.0))
        except (ValueError, TypeError):
            value = 0.0
            
        currency = webhook_data.get('currency', 'SEK')
        if currency: currency = currency.upper()

        # --- 3. Parse Browser & External ID data ---
        client_ip = webhook_data.get('browser_ip')
        
        # FIX: Handle if client_details is explicitly None
        client_details = webhook_data.get('client_details') or {}
        client_user_agent = client_details.get('user_agent')
        
        order_id_str = str(webhook_data.get('id', '')) 

        logging.info(
            "Celery worker: Extracted PII: email=%s, name=%s, ip=%s, ua=%s",
            bool(email), bool(full_name), bool(client_ip), bool(client_user_agent)
        )

        # --- 4. Build the CAPI Payload ---
        user_data = {
            "em": hash_data(email or ""),
            "fn": hash_data(first_name or ""),
            "ln": hash_data(last_name or ""),
            "ph": hash_data(phone or ""),
            "ct": hash_data(city or ""),
            "zp": hash_data(postal_code or ""),
            "country": hash_data(country_code or ""),
            "client_ip_address": (client_ip or None),
            "client_user_agent": (client_user_agent or None),
            "external_id": hash_data(order_id_str),
        }
        # Remove empty fields
        user_data = {k: v for k, v in user_data.items() if v}

        custom_data = {
            "currency": currency,
            "value": value
        }

        event_id = f"shopify_{order_id_str}" 

        meta_purchase_event = {
            "event_name": "Purchase",
            "event_time": int(time.time()),
            "action_source": "website",
            "user_data": user_data,
            "custom_data": custom_data,
            "event_id": event_id
        }

        # --- 5. Send to Meta CAPI ---
        logging.info("Celery worker: Sending processed event to Meta CAPI.")
        send_to_meta_capi(meta_purchase_event)

        logging.info("Celery worker: Successfully processed and sent Shopify event.")
        return {"status": "success", "event_id": meta_purchase_event["event_id"]}
    
    except Exception as e:
        logging.error(f"Celery worker: Failed to process Shopify webhook: {str(e)}", exc_info=True)
        # Optional: raise e if you want Celery to mark it as FAILURE and potentially retry
        raise e