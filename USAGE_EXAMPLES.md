# Usage Examples - Cipher & DNS Checkers

This document provides usage examples for the new cipher and DNS checking modules.

## Table of Contents
- [Module Overview](#module-overview)
- [Cipher Checker Examples](#cipher-checker-examples)
- [DNS Checker Examples](#dns-checker-examples)
- [API Integration Examples](#api-integration-examples)
- [Testing](#testing)

---

## Module Overview

### Cipher Checker (`cipher_checker.py`)
Analyzes TLS cipher suites and protocol versions to assess encryption strength.

**Key Features:**
- Detects TLS version (1.0, 1.1, 1.2, 1.3)
- Enumerates supported cipher suites
- Identifies weak/deprecated ciphers
- Provides a normalized strength score (0.0-1.0)

### DNS Checker (`dns_checker.py`)
Verifies DNS configuration and email security records.

**Key Features:**
- Queries A, AAAA, MX, NS, and TXT records
- Detects SPF, DMARC, and DKIM configuration
- Calculates DNS reliability score (0.0-1.0)
- Provides configuration recommendations

---

## Cipher Checker Examples

### Basic Usage

```python
from cipher_checker import check_ciphers

# Check ciphers for a domain
result = check_ciphers("example.com")

print(f"Cipher Score: {result['cipher_score']}")
print(f"Protocol: {result['protocol_version']}")
print(f"Strength: {result['cipher_strength']}")
print(f"Supported Ciphers: {len(result['supported_ciphers'])}")

# Check for weak ciphers
if result['weak_ciphers_found']:
    print(f"⚠️ Weak ciphers detected: {result['weak_ciphers_found']}")

# View recommendations
for rec in result['recommendations']:
    print(f"📋 {rec}")
```

### Checking with Full URL

```python
# Works with full URLs
result = check_ciphers("https://www.github.com", timeout=10)

if result['error']:
    print(f"Error: {result['error']}")
else:
    print(f"✅ Cipher check complete")
    print(f"Score: {result['cipher_score']:.2f}")
```

### Detailed Cipher Analysis

```python
from cipher_checker import get_detailed_cipher_info

# Get protocol-specific details
details = get_detailed_cipher_info("example.com")

for protocol, info in details.items():
    if info.get('supported'):
        print(f"{protocol}: {info['cipher']} ({info['bits']} bits)")
    else:
        print(f"{protocol}: Not supported - {info.get('error', 'N/A')}")
```

### Example Output

```json
{
  "supported_ciphers": [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
  ],
  "protocol_version": "TLSv1.3",
  "cipher_score": 0.95,
  "cipher_strength": "strong",
  "weak_ciphers_found": [],
  "recommendations": [
    "Excellent: Using TLS 1.3 with modern ciphers"
  ],
  "error": null
}
```

---

## DNS Checker Examples

### Basic Usage

```python
from dns_checker import check_dns_records

# Check DNS records
result = check_dns_records("example.com")

print(f"DNS Score: {result['dns_score']}")
print(f"Reliability: {result['dns_reliability']}")
print(f"A Records: {len(result['a_records'])}")
print(f"MX Records: {len(result['mx_records'])}")
print(f"NS Records: {len(result['ns_records'])}")

# Check email security
if result['spf_record']:
    print(f"✅ SPF: {result['spf_record']}")
else:
    print("❌ No SPF record found")

if result['dmarc_record']:
    print(f"✅ DMARC: {result['dmarc_record']}")
else:
    print("❌ No DMARC record found")

if result['dkim_configured']:
    print("✅ DKIM is configured")
else:
    print("❌ DKIM not detected")
```

### Detailed Record Inspection

```python
result = check_dns_records("example.com", timeout=10)

# Print all A records (IPv4)
print("\n📍 IPv4 Addresses:")
for ip in result['a_records']:
    print(f"  - {ip}")

# Print all AAAA records (IPv6)
print("\n📍 IPv6 Addresses:")
for ip in result['aaaa_records']:
    print(f"  - {ip}")

# Print MX records with priority
print("\n📧 Mail Servers:")
for mx in result['mx_records']:
    print(f"  - Priority {mx['priority']}: {mx['host']}")

# Print nameservers
print("\n🌐 Nameservers:")
for ns in result['ns_records']:
    print(f"  - {ns}")

# Print all TXT records
print("\n📄 TXT Records:")
for txt in result['txt_records']:
    print(f"  - {txt}")
```

### DNSSEC Verification

```python
from dns_checker import verify_dnssec

# Check if DNSSEC is enabled
dnssec = verify_dnssec("cloudflare.com")

if dnssec['dnssec_enabled']:
    print("✅ DNSSEC is enabled")
    print(f"DS Records: {len(dnssec['ds_records'])}")
    for ds in dnssec['ds_records']:
        print(f"  - {ds}")
else:
    print("❌ DNSSEC is not enabled")
```

### Example Output

```json
{
  "a_records": ["93.184.216.34"],
  "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
  "mx_records": [
    {"priority": 10, "host": "mail1.example.com"},
    {"priority": 20, "host": "mail2.example.com"}
  ],
  "ns_records": ["ns1.example.com", "ns2.example.com"],
  "txt_records": ["v=spf1 include:_spf.example.com ~all"],
  "spf_record": "v=spf1 include:_spf.example.com ~all",
  "dmarc_record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
  "dkim_configured": true,
  "dns_score": 0.95,
  "dns_reliability": "high",
  "recommendations": [
    "Excellent DNS configuration with security features"
  ],
  "error": null
}
```

---

## API Integration Examples

### Complete Site Check (Flask Endpoint)

```bash
# Make a POST request to the /check endpoint
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com"}'
```

**Response:**

```json
{
  "url": "https://github.com",
  "domain": "github.com",
  "domain_age_years": 15.2,
  "ssl_valid": true,
  "ssl_issuer": "DigiCert",
  "ssl_expiry": "2025-12-31",
  "ssl_days_remaining": 365,

  "cipher_score": 0.95,
  "cipher_strength": "strong",
  "protocol_version": "TLSv1.3",
  "supported_ciphers": [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_AES_256_GCM_SHA384"
  ],
  "weak_ciphers_found": [],
  "cipher_recommendations": [
    "Excellent: Using TLS 1.3 with modern ciphers"
  ],

  "dns_score": 0.90,
  "dns_reliability": "high",
  "a_records": ["140.82.121.4"],
  "mx_records": [
    {"priority": 10, "host": "aspmx.l.google.com"}
  ],
  "ns_records": ["ns1.github.com", "ns2.github.com"],
  "spf_record": "v=spf1 include:_spf.google.com ~all",
  "dmarc_record": "v=DMARC1; p=reject",
  "dkim_configured": true,
  "dns_recommendations": [
    "Excellent DNS configuration with security features"
  ],

  "score": 88.5,
  "trust_level": "high",
  "checked_at": "2025-01-15T10:30:00"
}
```

### Python Requests Example

```python
import requests

# Check a website
response = requests.post(
    "http://localhost:5000/check",
    json={"url": "https://example.com"}
)

data = response.json()

# Access new cipher data
print(f"Cipher Score: {data['cipher_score']}")
print(f"Protocol: {data['protocol_version']}")
print(f"Cipher Strength: {data['cipher_strength']}")

# Access new DNS data
print(f"DNS Score: {data['dns_score']}")
print(f"DNS Reliability: {data['dns_reliability']}")
print(f"SPF Record: {data['spf_record']}")

# Overall score (incorporates all metrics)
print(f"Overall Trust Score: {data['score']}")
print(f"Trust Level: {data['trust_level']}")
```

### JavaScript Fetch Example

```javascript
// Check a website from the browser extension
fetch('http://localhost:5000/check', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ url: 'https://example.com' })
})
.then(response => response.json())
.then(data => {
  console.log('Cipher Score:', data.cipher_score);
  console.log('DNS Score:', data.dns_score);
  console.log('Overall Score:', data.score);
  console.log('Trust Level:', data.trust_level);

  // Display cipher recommendations
  data.cipher_recommendations.forEach(rec => {
    console.log('Cipher Rec:', rec);
  });

  // Display DNS recommendations
  data.dns_recommendations.forEach(rec => {
    console.log('DNS Rec:', rec);
  });
})
.catch(error => console.error('Error:', error));
```

---

## Testing

### Running Unit Tests

```bash
# Run all tests
cd backend
python -m pytest tests/test_cipher_dns_checkers.py -v

# Run specific test class
python -m pytest tests/test_cipher_dns_checkers.py::TestCipherChecker -v

# Run with coverage
python -m pytest tests/test_cipher_dns_checkers.py --cov=cipher_checker --cov=dns_checker
```

### Manual Testing

```python
# Test cipher checker manually
from cipher_checker import check_ciphers

# Test on known good sites
good_sites = ["google.com", "github.com", "cloudflare.com"]
for site in good_sites:
    result = check_ciphers(site, timeout=10)
    print(f"{site}: Score={result['cipher_score']}, Strength={result['cipher_strength']}")

# Test DNS checker manually
from dns_checker import check_dns_records

# Test on known good sites
for site in good_sites:
    result = check_dns_records(site, timeout=10)
    print(f"{site}: DNS Score={result['dns_score']}, Reliability={result['dns_reliability']}")
```

---

## Error Handling Examples

### Handling Connection Errors

```python
from cipher_checker import check_ciphers
from dns_checker import check_dns_records

domain = "invalid-domain-xyz.com"

# Cipher check with error handling
cipher_result = check_ciphers(domain, timeout=5)
if cipher_result['error']:
    print(f"Cipher check failed: {cipher_result['error']}")
    print(f"Score defaulted to: {cipher_result['cipher_score']}")
else:
    print("Cipher check succeeded!")

# DNS check with error handling
dns_result = check_dns_records(domain, timeout=5)
if dns_result['error']:
    print(f"DNS check failed: {dns_result['error']}")
    print(f"Score defaulted to: {dns_result['dns_score']}")
else:
    print("DNS check succeeded!")
```

### Timeout Handling

```python
import time

def check_with_retry(domain, max_retries=3):
    """Check cipher/DNS with retry logic"""

    for attempt in range(max_retries):
        print(f"Attempt {attempt + 1}/{max_retries}")

        cipher_result = check_ciphers(domain, timeout=10)
        dns_result = check_dns_records(domain, timeout=10)

        # Check if both succeeded
        if not cipher_result['error'] and not dns_result['error']:
            return cipher_result, dns_result

        # Wait before retry
        if attempt < max_retries - 1:
            time.sleep(2)

    return cipher_result, dns_result

# Use retry logic
cipher_data, dns_data = check_with_retry("example.com")
```

---

## Scoring Weight Customization

### Adjusting Composite Score Weights

```python
from score_calculator import ScoreCalculator

# Create calculator with custom weights
calculator = ScoreCalculator(
    domain_weight=0.30,   # 30% weight on domain age
    ssl_weight=0.30,      # 30% weight on SSL validity
    cipher_weight=0.25,   # 25% weight on cipher strength
    dns_weight=0.15       # 15% weight on DNS configuration
)

# Calculate score with custom weights
domain_data = {"domain_age_years": 5.2}
ssl_data = {"valid": True, "days_until_expiry": 90}
cipher_data = {"cipher_score": 0.9, "cipher_strength": "strong"}
dns_data = {"dns_score": 0.85, "dns_reliability": "high"}

result = calculator.calculate_score(
    domain_data,
    ssl_data,
    cipher_data,
    dns_data
)

print(f"Composite Score: {result['composite_score']}")
print(f"Trust Level: {result['trust_level']}")
print(f"Weights Used: {result['weights']}")
```

---

## Integration with Existing Code

### Updating app.py to Include New Checks

The `app.py` has been updated to automatically include cipher and DNS checks. Here's what changed:

```python
# OLD CODE (before):
ssl_info = safe_check_ssl(url)
score_data = safe_calculate_composite_score(
    domain_age_years=domain_age_years,
    ssl_valid=ssl_info.get("valid", False),
    ssl_days_remaining=ssl_info.get("days_until_expiry", 0),
    ssl_issuer=ssl_info.get("issuer", "")
)

# NEW CODE (after):
ssl_info = safe_check_ssl(url)
cipher_info = safe_check_ciphers(domain)  # NEW
dns_info = safe_check_dns(domain)         # NEW

score_data = safe_calculate_composite_score(
    domain_age_years=domain_age_years,
    ssl_valid=ssl_info.get("valid", False),
    ssl_days_remaining=ssl_info.get("days_until_expiry", 0),
    ssl_issuer=ssl_info.get("issuer", ""),
    cipher_score=cipher_info.get("cipher_score", 0.0),  # NEW
    dns_score=dns_info.get("dns_score", 0.0)            # NEW
)
```

### Response Structure Changes

The `/check` endpoint now returns additional fields:

```json
{
  // ... existing fields ...

  // NEW: Cipher information
  "cipher_score": 0.95,
  "cipher_strength": "strong",
  "protocol_version": "TLSv1.3",
  "supported_ciphers": ["..."],
  "weak_ciphers_found": [],
  "cipher_recommendations": ["..."],

  // NEW: DNS information
  "dns_score": 0.90,
  "dns_reliability": "high",
  "a_records": ["..."],
  "aaaa_records": ["..."],
  "mx_records": [{"priority": 10, "host": "..."}],
  "ns_records": ["..."],
  "spf_record": "v=spf1 ...",
  "dmarc_record": "v=DMARC1 ...",
  "dkim_configured": true,
  "dns_recommendations": ["..."]
}
```

---

## Performance Considerations

### Parallel Execution

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_multiple_domains(domains):
    """Check multiple domains in parallel"""
    results = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all tasks
        future_to_domain = {
            executor.submit(check_ciphers, domain): domain
            for domain in domains
        }

        # Collect results
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                results[domain] = {"error": str(e)}

    return results

# Check multiple sites
domains = ["google.com", "github.com", "stackoverflow.com"]
results = check_multiple_domains(domains)

for domain, result in results.items():
    print(f"{domain}: {result['cipher_score']}")
```

### Caching Results

```python
import time
from functools import lru_cache

@lru_cache(maxsize=128)
def cached_cipher_check(domain, timeout=10):
    """Cached cipher check (valid for process lifetime)"""
    return check_ciphers(domain, timeout)

@lru_cache(maxsize=128)
def cached_dns_check(domain, timeout=10):
    """Cached DNS check (valid for process lifetime)"""
    return check_dns_records(domain, timeout)

# First call - makes actual request
result1 = cached_cipher_check("example.com")
print("First call completed")

# Second call - returns cached result (instant)
result2 = cached_cipher_check("example.com")
print("Second call completed (cached)")
```

---

## Troubleshooting

### Common Issues

**Issue 1: DNS Resolution Fails**
```python
# Solution: Increase timeout or check network connectivity
result = check_dns_records("example.com", timeout=15)
```

**Issue 2: Cipher Enumeration Returns Empty List**
```python
# Some servers don't expose shared ciphers
# The module will still return the negotiated cipher
if len(result['supported_ciphers']) == 0:
    print("Server doesn't expose cipher list")
    print(f"But negotiated: {result['protocol_version']}")
```

**Issue 3: Import Errors**
```bash
# Install missing dependencies
pip install dnspython==2.7.0
pip install pyOpenSSL
```

### Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Now checks will output detailed logs
result = check_ciphers("example.com")
result = check_dns_records("example.com")
```

---

## Best Practices

1. **Always set reasonable timeouts** (5-10 seconds)
2. **Handle errors gracefully** - both modules return error fields
3. **Cache results** - DNS/cipher info doesn't change frequently
4. **Use parallel execution** for batch checks
5. **Monitor performance** - adjust timeouts based on your needs
6. **Validate inputs** - ensure domains are properly formatted
7. **Log failures** - track which checks fail for debugging

---

## Summary

The new cipher and DNS checkers provide comprehensive security analysis:

- **Cipher Checker**: Identifies encryption weaknesses and outdated protocols
- **DNS Checker**: Verifies proper DNS configuration and email security
- **Integrated Scoring**: Both contribute to the overall trust score
- **Error Resilient**: Graceful degradation if checks fail
- **Easy to Use**: Simple function calls with detailed responses

For more information, see:
- `cipher_checker.py` - Full cipher checking implementation
- `dns_checker.py` - Full DNS checking implementation
- `score_calculator.py` - Updated scoring algorithm
- `test_cipher_dns_checkers.py` - Comprehensive test suite
