import { register } from '@shopify/web-pixels-extension';

// Helper function to parse cookies
const getCookie = (name, browser) => {
  // Use the sandboxed browser.cookie API
  // This is an async function
  return browser.cookie.get()
    .then((cookies) => {
      const cookie = cookies.find(c => c.name === name);
      return cookie ? cookie.value : null;
    })
    .catch(() => null);
};

register(({ analytics, browser, settings, init }) => {
  const PIXEL_ENDPOINT_URL = "https://shopify-webhook-server-xdj2.onrender.com";

  // We only care about the 'checkout_completed' event
  analytics.subscribe('checkout_completed', async (event) => {
    
    // --- 1. Get Browser Data ---
    const fbp =  await getCookie('_fbp', browser); // Example: "fb.1.1668019200.234567890";
    const fbc =  await getCookie('_fbc', browser); // Example: "fb.1.1668019200.AOS.CLICK_ID.234567890123";

    const eventSourceUrl = event.context.document.location.href;
    const userAgent = event.context.navigator.userAgent;
    
    // --- 2. Get PII & Custom Data ---
    const checkout = event.data?.checkout;
    if (!checkout) {
      console.log("Meta CAPI Pixel: No checkout data found.");
      return;
    }

    const order = checkout.order;
    const orderId = order?.id?.split('/').pop(); // Extract number from GID
    const sharedId = `shopify_${orderId}`;
    const email = checkout.email;
    const phone = checkout.customer?.phone ||
                  checkout.shippingAddress?.phone ||
                  checkout.billingAddress?.phone;
    const address = checkout.shippingAddress || checkout.billingAddress;
    const customData = {
      value: checkout.totalPrice?.amount,
      currency: checkout.currencyCode,
    };

    // --- 3. Build User Data Payload (matches Python model) ---
    const user_data = {
      // Browser data
      fbp: fbp,
      fbc: fbc,
      user_agent: userAgent,
      // IP address will be added by FastAPI server

      // PII
      em: email,
      ph: phone,
      fn: address?.firstName,
      ln: address?.lastName,
      ct: address?.city,
      zp: address?.zip,
      country: address?.countryCode,
      external_id: sharedId // Using shared Id from order Id for advanced matching
    };

    // --- 4. Build Final Event Payload (matches Python model) ---
    const payload = {
      event_name: "Purchase",
      event_time: Math.floor(new Date(event.timestamp).getTime() / 1000),
      event_source_url: eventSourceUrl,
      action_source: "website",
      user_data: user_data,
      custom_data: customData,
      // The "Golden Thread" for deduplication
      event_id: sharedId // Using shared Id from order Id for deduplication
    };

    // --- 5. Send to Server ---
    if (!PIXEL_ENDPOINT_URL) {
      console.log("Meta CAPI Pixel: Endpoint URL is not set.");
      return;
    }
    
    // Use fetch (with keepalive) to send data to the Render server
    try {
      fetch(`${PIXEL_ENDPOINT_URL}/process-event`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true, // Ensures request completes even if user navigates away
      });
    } catch (error) {
      console.error("Meta CAPI Pixel: Error sending event:", error);
    }
  });
});