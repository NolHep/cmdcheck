"""Stripe billing helpers — test-mode Stripe Checkout, webhooks, and Customer Portal."""

from __future__ import annotations

import logging
import os
from typing import Any

import stripe

logger = logging.getLogger(__name__)

# Tier slug → Stripe Price ID (set in dashboard, stored in env)
PRICE_IDS: dict[str, str] = {
    "individual": os.getenv("STRIPE_PRICE_ID_INDIVIDUAL", ""),
    "teams": os.getenv("STRIPE_PRICE_ID_TEAMS", ""),
}

# Reverse map: Price ID → tier slug (populated at startup from PRICE_IDS)
_PRICE_TO_TIER: dict[str, str] = {}


def init(secret_key: str) -> None:
    """Call once at startup with the Stripe secret key."""
    stripe.api_key = secret_key
    _PRICE_TO_TIER.clear()
    for tier, price_id in PRICE_IDS.items():
        if price_id:
            _PRICE_TO_TIER[price_id] = tier
    logger.info("Stripe initialized (test_mode=%s)", secret_key.startswith("sk_test_"))


def is_configured() -> bool:
    return bool(stripe.api_key)


def get_or_create_customer(email: str) -> str:
    """Return an existing Stripe customer ID for this email, or create one."""
    existing = stripe.Customer.list(email=email, limit=1)
    if existing.data:
        return existing.data[0].id
    customer = stripe.Customer.create(email=email)
    return customer.id


def create_checkout_session(
    customer_id: str,
    price_id: str,
    success_url: str,
    cancel_url: str,
) -> str:
    """Create a Stripe Checkout Session and return the hosted URL."""
    session = stripe.checkout.Session.create(
        customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=cancel_url,
        allow_promotion_codes=True,
        billing_address_collection="auto",
    )
    return session.url  # type: ignore[return-value]


def create_portal_session(customer_id: str, return_url: str) -> str:
    """Create a Stripe Customer Portal session and return the URL."""
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )
    return session.url


def construct_webhook_event(payload: bytes, sig_header: str) -> stripe.Event:
    """Verify Stripe webhook signature and return the parsed event."""
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    return stripe.Webhook.construct_event(payload, sig_header, secret)  # type: ignore[return-value]


def tier_for_price(price_id: str) -> str:
    """Map a Stripe Price ID back to a tier slug, defaulting to 'unknown'."""
    return _PRICE_TO_TIER.get(price_id, "unknown")


def extract_subscription_info(subscription: Any) -> tuple[str, str]:
    """Return (status, tier) from a Stripe Subscription object."""
    status: str = subscription.status  # active, past_due, canceled, …
    tier = "free"
    if subscription.items and subscription.items.data:
        price_id = subscription.items.data[0].price.id
        tier = tier_for_price(price_id) or "unknown"
    return status, tier
