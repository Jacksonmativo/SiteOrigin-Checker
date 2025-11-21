# Exception handling fixes and guidelines

This document contains suggested fixes for common Bandit findings related to broad
exception handling in the codebase (e.g. B110, B112). It is documentation only and
not imported by the application. Apply these patterns to `dns_checker.py`,
`cipher_checker.py`, and `whois_checker.py` where appropriate.

Summary of recommendations:

- Replace bare `except Exception:` with specific exception types where possible
- Log expected failures at `debug` level and unexpected issues at `warning`/`error`
- If swallowing an exception is intentional, add a `# nosec B110` or `# nosec B112`
  comment with a short justification
- Return sensible defaults instead of silently continuing with undefined state

Examples (illustrative only):

1) Replace `except Exception: pass` with specific exceptions and logging:

```py
try:
    result['supported_ciphers'] = [cipher_info[0]]
except (IndexError, TypeError) as e:
    logger.debug("Cipher info parsing failed: %s", e)
    result['supported_ciphers'] = []
```

2) For loops where you try multiple formats, catch `ValueError` not `Exception`:

```py
for fmt in date_formats:
    try:
        return datetime.strptime(date_str.strip(), fmt)
    except ValueError:
        continue
```

3) When dealing with DNS lookups, prefer `dns.exception.DNSException` or
   resolver-specific exceptions:

```py
try:
    dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
except dns.exception.DNSException as e:
    logger.debug("DMARC lookup failed: %s", e)
```

4) If this file is intentionally a knowledge artifact rather than runtime code,
   keep it in `docs/` (as done here) so static analyzers won't flag it.

These guidelines help keep error handling explicit and maintain useful logs
for debugging while avoiding silent failures.
