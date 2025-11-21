#!/usr/bin/env python3
"""
Direct SSL checker test - no Flask involved
"""
import sys
import json
import logging

# Setup logging to see what's happening
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

try:
    from backend.ssl_checker import check_ssl_certificate
    print("✓ Successfully imported check_ssl_certificate")
except ImportError as e:
    print(f"✗ Failed to import ssl_checker: {e}")
    sys.exit(1)


def run_ssl(url):
    print("\n" + "="*70)
    print(f"Testing: {url}")
    print("="*70)

    try:
        print(f"Calling check_ssl_certificate('{url}', timeout=10)...")
        result = check_ssl_certificate(url, timeout=10)

        print(f"\nResult type: {type(result)}")
        print(f"Result: {json.dumps(result, indent=2, default=str)}")

        # Check each field
        print("\n--- Field Analysis ---")
        print(
            f"valid: {result.get('valid')} "
            f"(type: {type(result.get('valid'))})"
        )
        print(
            f"issuer: {result.get('issuer')} "
            f"(type: {type(result.get('issuer'))})"
        )
        print(
            f"expiry_date: {result.get('expiry_date')} "
            f"(type: {type(result.get('expiry_date'))})"
        )
        print(
            f"days_until_expiry: {result.get('days_until_expiry')} "
            f"(type: {type(result.get('days_until_expiry'))})"
        )
        print(f"error: {result.get('error')}")

        if result.get('valid'):
            print("\n✅ SSL is VALID")
        else:
            print("\n❌ SSL is INVALID")
            if result.get('error'):
                print(f"   Reason: {result['error']}")

    except Exception as e:
        print(f"\n❌ Exception occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://google.com",
        "https://github.com",
        "https://www.cloudflare.com",
    ]

    if len(sys.argv) > 1:
        test_urls = [sys.argv[1]]

    for url in test_urls:
        run_ssl(url)

    print("\n" + "="*70)
    print("Testing complete!")
    print("="*70)

