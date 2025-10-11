# Security Testing Plan: SiteOrigin Checker

## 1. Extension-Specific Security Tests

### 1.1 Content Security Policy (CSP)
- [ ] Verify manifest.json has proper CSP directives
- [ ] Test that inline scripts are blocked
- [ ] Ensure no `eval()` or `Function()` constructors are used
- [ ] Verify external resources are loaded only from allowed domains

**Test Commands:**
```bash
# Check for dangerous patterns in extension code
grep -r "eval(" extension/
grep -r "innerHTML" extension/
grep -r "document.write" extension/
```

### 1.2 Permission Abuse
- [ ] Review manifest.json permissions - ensure minimal necessary permissions
- [ ] Test that extension doesn't access tabs it shouldn't
- [ ] Verify storage API only stores necessary data
- [ ] Check that sensitive data isn't logged to console

**Current Permissions to Validate:**
```json
"permissions": ["activeTab", "storage", "tabs"]
"host_permissions": ["http://localhost:5000/*"]
```

### 1.3 XSS in Extension Context
- [ ] Test popup.html with malicious data injection
- [ ] Inject XSS payloads into trust badge rendering
- [ ] Test contentScript.js DOM manipulation with malicious URLs
- [ ] Verify user-controlled data is properly sanitized

**Test Payloads:**
```javascript
// Test URLs to send to your extension
const xssTests = [
  'https://example.com/<script>alert(1)</script>',
  'https://example.com/"><img src=x onerror=alert(1)>',
  'javascript:alert(document.cookie)',
  'data:text/html,<script>alert(1)</script>'
];
```

## 2. Backend API Security Tests

### 2.1 Input Validation & Injection
- [ ] Test SQL injection (if using database)
- [ ] Test command injection in WHOIS/SSL checks
- [ ] Test path traversal attacks
- [ ] Test XXE attacks (if parsing XML)
- [ ] Test SSRF (Server-Side Request Forgery)

**Critical SSRF Test Cases:**
```bash
# Test internal network access
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:22"}'

curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "file:///etc/passwd"}'

# Test localhost variations
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "http://0.0.0.0:5000"}'
```

### 2.2 Command Injection in WHOIS/SSL Checks
- [ ] Test shell metacharacters in domain names
- [ ] Verify subprocess calls are properly sanitized

**Test Payloads:**
```bash
# Command injection attempts
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com;ls"}'

curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com|whoami"}'

curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com`id`"}'
```

### 2.3 CORS Configuration
- [ ] Test CORS headers are properly configured
- [ ] Verify only extension origin is allowed
- [ ] Test that credentials aren't accepted from unauthorized origins

**Test Script:**
```javascript
// Test from browser console on different origin
fetch('http://localhost:5000/check', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'https://example.com'})
}).then(r => r.json()).then(console.log);
```

### 2.4 Rate Limiting & DoS
- [ ] Test rate limiting implementation
- [ ] Send rapid repeated requests
- [ ] Test with very long URLs
- [ ] Test with malformed JSON

**Load Test:**
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test rate limiting
ab -n 1000 -c 10 -p payload.json -T application/json \
  http://localhost:5000/check
```

## 3. SSL/TLS Validation Security

### 3.1 Certificate Validation Bypass
- [ ] Test with self-signed certificates
- [ ] Test with expired certificates
- [ ] Test with wrong hostname
- [ ] Verify certificate chain validation

**Python Test Script:**
```python
import ssl
import socket

# Test that your checker properly rejects invalid certs
test_cases = [
    ('expired.badssl.com', 443),
    ('wrong.host.badssl.com', 443),
    ('self-signed.badssl.com', 443),
    ('untrusted-root.badssl.com', 443)
]

for host, port in test_cases:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"{host}: {ssock.version()}")
    except ssl.SSLError as e:
        print(f"{host}: Properly rejected - {e}")
```

## 4. Data Privacy & Leakage

### 4.1 Sensitive Data Exposure
- [ ] Check browser console for logged URLs
- [ ] Verify no sensitive data in extension storage
- [ ] Test cache doesn't persist sensitive information
- [ ] Verify API responses don't leak internal info

**Storage Inspection:**
```javascript
// Run in extension background page console
chrome.storage.local.get(null, (data) => {
  console.log('Stored data:', data);
});
```

### 4.2 Information Disclosure
- [ ] Test error messages don't reveal system info
- [ ] Verify stack traces aren't exposed
- [ ] Check HTTP headers don't leak versions
- [ ] Test API endpoints for verbose errors

## 5. Authentication & Authorization

### 5.1 API Authentication (if implemented)
- [ ] Test API without authentication
- [ ] Test with invalid API keys
- [ ] Test privilege escalation
- [ ] Verify token expiration

### 5.2 Origin Validation
- [ ] Verify backend only accepts requests from extension
- [ ] Test cross-origin requests are blocked
- [ ] Validate Referer/Origin headers

## 6. Dependency Vulnerabilities

### 6.1 Python Dependencies
```bash
# Install safety checker
pip install safety

# Check for known vulnerabilities
safety check --file requirements.txt

# Alternative: use pip-audit
pip install pip-audit
pip-audit
```

### 6.2 JavaScript Dependencies
```bash
# If you add npm packages later
npm audit
npm audit fix
```

### 6.3 Manual Dependency Review
- [ ] Review python-whois library security advisories
- [ ] Check Flask/FastAPI CVE database
- [ ] Monitor Chrome Extension API changes

## 7. Business Logic Vulnerabilities

### 7.1 Score Manipulation
- [ ] Test if scores can be manipulated by controlling responses
- [ ] Verify score calculation logic is server-side
- [ ] Test edge cases in scoring algorithm

### 7.2 Cache Poisoning
- [ ] Test if malicious data can poison cache
- [ ] Verify cache keys are properly unique
- [ ] Test cache invalidation works correctly

**Test Cache Poisoning:**
```bash
# Send malicious data, then verify it doesn't affect other users
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
# Check if cached response is reused for different contexts
```

## 8. Automated Security Scanning

### 8.1 SAST (Static Analysis)
```bash
# Install Bandit for Python
pip install bandit
bandit -r backend/ -f json -o security-report.json

# Install Semgrep
pip install semgrep
semgrep --config=auto backend/
```

### 8.2 DAST (Dynamic Analysis)
```bash
# Install OWASP ZAP
# Run automated scan against your backend
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:5000 -r zap-report.html
```

### 8.3 Extension Security Scanner
- Use Google's Extension Security Analyzer
- Run CSP Evaluator: https://csp-evaluator.withgoogle.com/

## 9. Manual Code Review Checklist

### Backend (Python)
- [ ] Review `app.py` for input validation
- [ ] Check `whois_checker.py` for command injection
- [ ] Review `ssl_checker.py` for certificate validation
- [ ] Verify `score_calculator.py` doesn't have logic flaws
- [ ] Check all subprocess calls use proper sanitization
- [ ] Verify file operations are secure
- [ ] Review error handling (no info leakage)

### Extension (JavaScript)
- [ ] Review `background.js` for secure message passing
- [ ] Check `contentScript.js` for DOM XSS
- [ ] Verify `popup.js` sanitizes displayed data
- [ ] Review manifest.json permissions
- [ ] Check for hardcoded secrets/API keys
- [ ] Verify storage API usage is secure

## 10. Penetration Testing Scenarios

### Scenario 1: Malicious Website Owner
**Goal:** Manipulate their own site to appear more trustworthy

Test Cases:
- [ ] Can they inject false WHOIS data?
- [ ] Can they present fake SSL certificates?
- [ ] Can they bypass domain age checks?

### Scenario 2: Attacker Targeting Extension Users
**Goal:** Exploit the extension to compromise users

Test Cases:
- [ ] Can they inject malicious code via search results?
- [ ] Can they perform XSS through the trust badge?
- [ ] Can they steal data from extension storage?

### Scenario 3: Backend Server Compromise
**Goal:** Attack the backend infrastructure

Test Cases:
- [ ] Can they perform SSRF to internal services?
- [ ] Can they DoS the backend?
- [ ] Can they extract sensitive configuration?

## 11. Security Testing Tools

### Recommended Tools
```bash
# Install testing toolkit
pip install requests pytest pytest-cov bandit safety
npm install -g retire snyk

# Extension testing
# Download from Chrome Web Store:
# - Extension Security Analyzer
# - Chrome DevTools
```

### Burp Suite Configuration
1. Configure browser to use Burp proxy
2. Intercept requests from extension to backend
3. Test for injection vulnerabilities
4. Check response manipulation

## 12. Compliance & Best Practices

### OWASP Top 10 Coverage
- [x] A01: Broken Access Control
- [x] A02: Cryptographic Failures
- [x] A03: Injection
- [x] A04: Insecure Design
- [x] A05: Security Misconfiguration
- [x] A06: Vulnerable Components
- [x] A07: Authentication Failures
- [x] A08: Software/Data Integrity
- [x] A09: Security Logging Failures
- [x] A10: SSRF

### Chrome Extension Security Checklist
- [ ] Uses Manifest V3
- [ ] Minimal permissions requested
- [ ] No remote code execution
- [ ] Proper CSP headers
- [ ] Secure message passing
- [ ] Input sanitization
- [ ] No sensitive data storage

## 13. Reporting & Documentation

### Security Test Report Template
```markdown
# Security Test Report - SiteOrigin Checker

**Date:** YYYY-MM-DD
**Tester:** Your Name
**Version Tested:** 1.0.0

## Executive Summary
[High-level findings]

## Vulnerabilities Found
| ID | Severity | Title | Description | Remediation |
|----|----------|-------|-------------|-------------|
| 001 | High | XSS in popup | ... | ... |

## Testing Coverage
- [x] Input Validation
- [x] Authentication
- [ ] ...

## Recommendations
1. Implement URL validation whitelist
2. Add rate limiting
3. ...
```

## 14. Continuous Security

### Pre-Commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: local
    hooks:
      - id: bandit
        name: bandit
        entry: bandit
        language: system
        args: ['-r', 'backend/']
EOF

# Install hooks
pre-commit install
```

### CI/CD Security Checks
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r backend/
      - name: Dependency Check
        run: |
          pip install safety
          safety check
```

---

## Priority Testing Order

### Critical (Test First)
1. SSRF in URL validation
2. Command injection in WHOIS/SSL checks
3. XSS in extension context
4. CORS misconfiguration

### High (Test Second)
5. Input validation bypass
6. Rate limiting effectiveness
7. Sensitive data exposure
8. Certificate validation bypass

### Medium (Test Third)
9. Cache poisoning
10. Information disclosure
11. Dependency vulnerabilities
12. Business logic flaws

---

**Start with automated scans, then perform manual testing of critical areas.**