from flask import Flask, request, jsonify
import hmac
import hashlib
import base64
import os

app = Flask(__name__)

# Set this in Render environment variables
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "your_secret_here")


def verify_webhook(data, hmac_header):
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        data,
        hashlib.sha256
    ).digest()

    computed_hmac = base64.b64encode(digest).decode()

    return hmac.compare_digest(computed_hmac, hmac_header)


@app.route("/", methods=["GET"])
def home():
    return "Shopify Webhook Listener Running"


@app.route("/webhook/orders/create", methods=["POST"])
def orders_create():
    data = request.get_data()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")

    if not verify_webhook(data, hmac_header):
        return jsonify({"error": "Invalid webhook signature"}), 401

    order = request.json

    # Example: print useful data
    print("New order received!")
    print("Order ID:", order.get("id"))
    print("Email:", order.get("email"))
    print("Total Price:", order.get("total_price"))

    # You can process/save/send this anywhere
    return jsonify({"status": "success"}), 200


if __name__ == "__main__":
    app.run(debug=True, port=os.getenv("PORT", default=5000))
