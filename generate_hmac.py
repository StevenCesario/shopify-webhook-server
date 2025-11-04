# generate_hmac.py
import hmac
import hashlib
import base64
import os
from dotenv import load_dotenv

# Load your .env file to get the secret
load_dotenv()
SHOPIFY_CLIENT_SECRET = os.getenv("SHOPIFY_CLIENT_SECRET")

if not SHOPIFY_CLIENT_SECRET:
    print("Error: SHOPIFY_CLIENT_SECRET not found in .env file.")
    print("Please make sure it's set!")
    exit(1)

try:
    with open("sample_payload_orders_create.json", "rb") as f:
        payload_body = f.read()
except FileNotFoundError:
    print("Error: sample_payload_orders_create.json not found.")
    print("Please create it and paste your test Shopify JSON payload inside.")
    exit(1)

# --- The same logic from main.py ---
hash_digest = hmac.new(
    SHOPIFY_CLIENT_SECRET.encode('utf-8'),
    payload_body,
    hashlib.sha256
).digest()

computed_hmac_b64 = base64.b64encode(hash_digest)

print("--- 🚀 Your Test HMAC Signature ---")
print("Copy this value into your 'X-Shopify-Hmac-SHA256' header in Postman:")
print(f"\n{computed_hmac_b64.decode('utf-8')}\n")