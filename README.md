# Open Webhook Registry

Machine-executable verification specifications for webhook providers.
Used by [AparHub](https://aparhub.com) to power automatic webhook verification — customers configure their source in minutes without reading provider documentation.

This is an open format. Contributions welcome.

---

## What this is

Each YAML file in `providers/` is a complete, machine-executable specification for one webhook provider. It describes:

- **How to verify** the signature (HMAC, asymmetric, JWT, shared secret, mTLS)
- **What the customer must configure** (secret, API key, verify token)
- **What events the provider sends** (pre-populated event filter)
- **A test harness** with known inputs and expected outputs for CI

The verification engine reads these specs and executes the correct strategy — no provider-specific code, no switch statements.

---

## Schema

The full JSON Schema is at [`schema/provider-spec.schema.json`](schema/provider-spec.schema.json).

### Key concepts

**`verification.primary`** — the primary strategy. One of:

| Type | Description | Tier |
|---|---|---|
| `hmac` | HMAC-SHA256/SHA512/SHA1 signature | Starter |
| `shared_secret` | Static token comparison | Starter |
| `asymmetric` | RSA/ECDSA/EdDSA signature | Scale+ |
| `jwt` | JWT validation with JWK | Scale+ |
| `dataless` | Minimal payload — fetch full event via API | Scale+ |
| `mtls` | Mutual TLS client certificate | Enterprise |

**`verification.registration_challenge`** — one-time verification run at source setup (Facebook, Zoom). Handled automatically by AparHub.

**`verification.replay_prevention`** — timestamp or nonce-based replay attack prevention. Layered on top of the primary strategy.

**CEL expressions** — `sig_value`, `signing_input`, `replay_check`, `timestamp_value` are [CEL](https://github.com/google/cel-spec) expressions evaluated against the request context:

```
raw_body          — raw request body bytes/string
header('Name')    — HTTP header value
query('param')    — query parameter value
body_field('key') — JSON body field
params.<field>    — customer-configured value
int(x)            — cast to integer
base64_encode(x)  — base64 encode
crc32(x)          — CRC32 checksum
```

**`test_harness`** — mandatory. CI validates every spec against its test harness before merge.

---

## Provider catalog

### India
| Provider | Strategy | Replay | Tier |
|---|---|---|---|
| [Razorpay](providers/india/razorpay.yaml) | HMAC-SHA256 hex | — | Starter |
| [Cashfree](providers/india/cashfree.yaml) | HMAC-SHA256 base64 | Timestamp | Starter |
| [PayU](providers/india/payu.yaml) | SHA-512 hex | — | Starter |
| [PhonePe](providers/india/phonepe.yaml) | SHA-256 hex | — | Starter |
| [Juspay](providers/india/juspay.yaml) | HMAC-SHA256 base64 | — | Starter |
| [BillDesk](providers/india/billdesk.yaml) | HMAC-SHA256 hex | — | Starter |

### Global
| Provider | Strategy | Add-ons | Tier |
|---|---|---|---|
| [Stripe](providers/global/stripe.yaml) | HMAC-SHA256 hex | Replay (timestamp) | Starter |
| [GitHub](providers/global/github.yaml) | HMAC-SHA256 hex | — | Starter |
| [Slack](providers/global/slack.yaml) | HMAC-SHA256 hex | Replay (timestamp) | Starter |
| [Facebook](providers/global/facebook.yaml) | HMAC-SHA1 hex | One-time verify | Starter |
| [Shopify](providers/global/shopify.yaml) | HMAC-SHA256 base64 | — | Starter |
| [PayPal](providers/global/paypal.yaml) | Asymmetric RSA | — | Scale+ |
| [Plaid](providers/global/plaid.yaml) | JWT ES256 (JWK) | — | Scale+ |

---

## Contributing a new provider

1. Fork this repo
2. Create `providers/<region>/<slug>.yaml`
3. Follow the schema — validate locally with `python3 tools/validate_specs.py providers/<region>/<slug>.yaml`
4. The test harness is **mandatory** — PRs without a passing test harness will not be merged
5. Open a PR — CI runs automatically

### Running validation locally

```bash
pip install jsonschema pyyaml
python3 tools/validate_specs.py                          # all providers
python3 tools/validate_specs.py providers/india/razorpay.yaml  # one file
```

### Generating test harness signatures

Use this to compute the expected signature for your test harness:

```bash
python3 tools/generate_test_sig.py \
  --provider providers/india/razorpay.yaml \
  --secret "test_secret" \
  --payload '{"event":"payment.captured"}'
```

---

## Relationship to Standard Webhooks

AparHub's outbound delivery (AparHub → customer destination) uses the [Standard Webhooks](https://standardwebhooks.com) header format:
- `webhook-id` — stable message ID
- `webhook-timestamp` — unix epoch
- `webhook-signature` — `v1,<base64_hmac_sha256(id.timestamp.body)>`

Providers that adopt Standard Webhooks get a near-trivial catalog entry — set `standard_webhooks: true` and omit `signing_input`.

This spec format covers the gap Standard Webhooks does not address: describing *existing* providers who predate or have not adopted the standard.

---

## License

Apache 2.0 — free to use, implement, and extend.
Contributions licensed under the same terms.
