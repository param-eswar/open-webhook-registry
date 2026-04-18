#!/usr/bin/env python3
"""
AparHub Webhook Provider Spec — Test Signature Generator

Computes the expected signature for a provider spec's test harness.
Run this when creating a new spec to generate the correct expected_signature value.

Usage:
    python3 generate_test_sig.py --provider providers/india/razorpay.yaml

The tool reads the spec, extracts the strategy params, and computes
the expected HMAC digest using the test_harness values.

For asymmetric/JWT providers, it outputs the signing input bytes
so you can compute the signature with your test key pair externally.
"""

import sys
import hmac
import hashlib
import base64
import yaml
import json
import re
import argparse
import pathlib
from typing import Any


def evaluate_cel_simple(expr: str, context: dict) -> str:
    """
    Simplified CEL evaluator for the subset of expressions used in provider specs.
    Covers: header(), raw_body, string concat (+), trimPrefix(), split(), filter(),
    startsWith(), first(), int(), base64_encode(), crc32()
    
    Not a full CEL implementation — covers the patterns in this catalog.
    """
    expr = expr.strip()
    
    # raw_body
    if expr == "raw_body":
        return context.get("raw_body", "")
    
    # String literal
    if expr.startswith("'") and expr.endswith("'"):
        return expr[1:-1]
    
    # int(x)
    m = re.fullmatch(r"int\((.+)\)", expr)
    if m:
        return evaluate_cel_simple(m.group(1), context)
    
    # base64_encode(x)
    m = re.fullmatch(r"base64_encode\((.+)\)", expr)
    if m:
        inner = evaluate_cel_simple(m.group(1), context)
        if isinstance(inner, bytes):
            return base64.b64encode(inner).decode()
        return base64.b64encode(inner.encode()).decode()
    
    # crc32(x)
    m = re.fullmatch(r"crc32\((.+)\)", expr)
    if m:
        import binascii
        inner = evaluate_cel_simple(m.group(1), context)
        data = inner.encode() if isinstance(inner, str) else inner
        return str(binascii.crc32(data) & 0xFFFFFFFF)
    
    # header('Name')
    m = re.fullmatch(r"header\('([^']+)'\)", expr)
    if m:
        return context.get("headers", {}).get(m.group(1), "")
    
    # .trimPrefix('prefix')
    m = re.match(r"^(.+)\.trimPrefix\('([^']*)'\)$", expr)
    if m:
        val = evaluate_cel_simple(m.group(1), context)
        prefix = m.group(2)
        return val.removeprefix(prefix) if val.startswith(prefix) else val
    
    # .split(',').filter(s, s.startsWith('v1=')).first().split('=', 2)[1]
    # Simplified: handle common Stripe-like patterns
    m = re.match(r"^(.+)\.split\('([^']*)'\)\.filter\(s,\s*s\.startsWith\('([^']*)'\)\)\.first\(\)\.split\('([^']*)'(?:,\s*(\d+))?\)\[(\d+)\]$", expr)
    if m:
        val = evaluate_cel_simple(m.group(1), context)
        sep = m.group(2)
        prefix = m.group(3)
        sep2 = m.group(4)
        maxsplit = int(m.group(5)) if m.group(5) else -1
        idx = int(m.group(6))
        parts = val.split(sep)
        filtered = [p for p in parts if p.startswith(prefix)]
        if not filtered:
            return ""
        first = filtered[0]
        parts2 = first.split(sep2, maxsplit) if maxsplit > 0 else first.split(sep2)
        return parts2[idx] if idx < len(parts2) else ""
    
    # String concatenation: expr + expr
    # Split on top-level + only (not inside function calls or strings)
    parts = split_concat(expr)
    if len(parts) > 1:
        return "".join(evaluate_cel_simple(p.strip(), context) for p in parts)
    
    return expr  # fallback — return as-is


def split_concat(expr: str) -> list[str]:
    """Split a CEL expression on top-level + operators."""
    parts = []
    depth = 0
    in_string = False
    current = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "'" and not in_string:
            in_string = True
            current.append(c)
        elif c == "'" and in_string:
            in_string = False
            current.append(c)
        elif c in "([" and not in_string:
            depth += 1
            current.append(c)
        elif c in ")]" and not in_string:
            depth -= 1
            current.append(c)
        elif c == "+" and depth == 0 and not in_string:
            parts.append("".join(current))
            current = []
        else:
            current.append(c)
        i += 1
    if current:
        parts.append("".join(current))
    return parts if len(parts) > 1 else [expr]


def compute_hmac(secret: str, data: str, algo: str, encoding: str, secret_encoding: str = "raw") -> str:
    """Compute HMAC and return the digest in the specified encoding."""
    # Decode the secret
    if secret_encoding == "base64":
        # Strip common prefixes (whsec_, etc.)
        raw = secret
        for prefix in ["whsec_", "whsec "]:
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break
        key = base64.b64decode(raw)
    elif secret_encoding == "hex":
        key = bytes.fromhex(secret)
    else:
        key = secret.encode()

    # Choose hash function
    hash_func = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha1": hashlib.sha1,
    }.get(algo)
    
    if not hash_func:
        raise ValueError(f"Unsupported algo: {algo}")

    data_bytes = data.encode() if isinstance(data, str) else data
    digest = hmac.new(key, data_bytes, hash_func).digest()

    if encoding == "hex":
        return digest.hex()
    elif encoding == "base64":
        return base64.b64encode(digest).decode()
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def process_spec(spec_path: pathlib.Path) -> None:
    spec = yaml.safe_load(open(spec_path))
    harness = spec.get("test_harness", {})
    primary = spec.get("verification", {}).get("primary", {})
    strategy_type = primary.get("type")

    print(f"\n{'═' * 60}")
    print(f"  {spec['name']}  ({spec['slug']})")
    print(f"  Strategy: {strategy_type}")
    print(f"{'═' * 60}\n")

    if strategy_type != "hmac":
        print(f"  Strategy '{strategy_type}' requires cryptographic key material beyond this tool.")
        print(f"  For asymmetric/JWT providers, the signing input bytes are:\n")
        
        context = {
            "raw_body": harness.get("sample_payload", ""),
            "headers": harness.get("sample_headers", {}),
        }
        
        signing_input_expr = primary.get("signing_input", "raw_body")
        signing_input = evaluate_cel_simple(signing_input_expr, context)
        print(f"  signing_input = {repr(signing_input[:100])}{'...' if len(signing_input) > 100 else ''}")
        print(f"\n  Use your test private key to sign this and populate expected_signature.")
        return

    # HMAC provider
    test_secret = harness.get("test_secret", "")
    sample_payload = harness.get("sample_payload", "")
    sample_headers = harness.get("sample_headers", {})

    context = {
        "raw_body": sample_payload,
        "headers": sample_headers,
        "params": {"webhook_secret": test_secret},
    }

    # Evaluate signing_input
    signing_input_expr = primary.get("signing_input", "raw_body")
    if spec.get("standard_webhooks"):
        msg_id = sample_headers.get("webhook-id", "test-msg-id")
        timestamp = sample_headers.get("webhook-timestamp", "1714000000")
        signing_input = f"{msg_id}.{timestamp}.{sample_payload}"
    else:
        signing_input = evaluate_cel_simple(signing_input_expr, context)

    algo = primary.get("algo", "sha256")
    encoding = primary.get("encoding", "hex")
    secret_encoding = primary.get("secret_encoding", "raw")

    print(f"  test_secret:    {test_secret}")
    print(f"  algo:           {algo}")
    print(f"  encoding:       {encoding}")
    print(f"  secret_encoding:{secret_encoding}")
    print(f"  signing_input:  {repr(signing_input[:120])}{'...' if len(signing_input) > 120 else ''}")
    print()

    try:
        computed = compute_hmac(test_secret, signing_input, algo, encoding, secret_encoding)
        print(f"  Computed digest: {computed}")

        # Show what the sig_value CEL extracts from sample_headers
        sig_val_expr = primary.get("sig_value", "")
        claimed = evaluate_cel_simple(sig_val_expr, context)
        print(f"  Claimed (from headers): {claimed}")
        
        if claimed == computed:
            print(f"\n  ✓ MATCH — test harness signature is correct")
        elif not claimed:
            print(f"\n  ⚠ No claimed signature in sample_headers — update test_harness.sample_headers")
            print(f"    Set the signature header to: {computed}")
        else:
            print(f"\n  ✗ MISMATCH — update test_harness.sample_headers")
            print(f"    Expected: {computed}")
            print(f"    Got:      {claimed}")
            
            # Generate the correct header entry
            sig_header = _extract_header_name(primary.get("sig_value", ""))
            if sig_header:
                prefix = _extract_prefix(primary.get("sig_value", ""))
                print(f"\n    Update sample_headers:")
                print(f"      {sig_header}: \"{prefix}{computed}\"")

    except Exception as e:
        print(f"  Error computing HMAC: {e}")


def _extract_header_name(sig_value_expr: str) -> str:
    """Extract the header name from a sig_value CEL expression."""
    m = re.search(r"header\('([^']+)'\)", sig_value_expr)
    return m.group(1) if m else ""


def _extract_prefix(sig_value_expr: str) -> str:
    """Detect if a known prefix should be prepended (e.g. sha256=, sha1=, v1=)."""
    # If trimPrefix is called, the stored value doesn't have the prefix
    # Return empty — the prefix is stripped before comparison
    if "trimPrefix" in sig_value_expr:
        m = re.search(r"trimPrefix\('([^']*)'\)", sig_value_expr)
        if m:
            return m.group(1)
    return ""


def main():
    parser = argparse.ArgumentParser(description="Compute expected HMAC signatures for test harnesses")
    parser.add_argument("--provider", required=False, help="Path to provider YAML. If omitted, runs all HMAC providers.")
    args = parser.parse_args()

    if args.provider:
        process_spec(pathlib.Path(args.provider))
    else:
        root = pathlib.Path(__file__).parent.parent
        for spec_path in sorted(root.glob("providers/**/*.yaml")):
            process_spec(spec_path)
    print()


if __name__ == "__main__":
    main()
