import logging
import time
import json
import os
from celery import Celery

# --- Helper functions from main.py ---
from main import hash_data, send_to_meta_capi, CAPI_URL

# --- Environment Variable for Celery Broker ---
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
        # TODO: To be verified against a real Shopify payload
        email = webhook_data.get('email')
        phone = webhook_data.get('phone')

        # Billing address
        billing_address = webhook_data.get('billing_address', {})
        full_name = billing_address.get('name', '')
        first_name, last_name = (full_name.split(' ', 1) + [''])[:2] # Safe split
        city = billing_address.get('city')
        postal_code = billing_address.get('zip')
        country_code = billing_address.get('country_code') # e.g., "SE"

        # --- 2. Parse Purchase Value ---
        value = float(webhook_data.get('total_price', 0.0))
        currency = webhook_data.get('currency', 'SEK').upper()

        logging.info("Celery worker: Extracted PII from Shopify: email=%s, name=%s", bool(email), bool(full_name))

        # --- 3. Build the CAPI Payload (reusing hash_data function) ---
        user_data = {
            "em": hash_data(email),
            "fn": hash_data(first_name),
            "ln": hash_data(last_name),
            "ph": hash_data(phone),
            "ct": hash_data(city),
            "zp": hash_data(postal_code),
            "country": hash_data(country_code)
        }
        # Remove any empty fields
        user_data = {k: v for k, v in user_data.items() if v}