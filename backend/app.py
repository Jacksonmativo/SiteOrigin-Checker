from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import logging
from whois_checker import WhoisChecker
from ssl_checker import check_ssl_certificate
from score_calculator import calculate_composite_score
import redis
import json
import hashlib
import socket
import ipaddress


from urllib.parse import urlparse
import requests


import os
import inspect
from celery_worker import celery_app


@celery_app.task
def process_site_check(url):

    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    if domain.startswith("www."):
        domain = domain[4:]

    domain_info = whois_checker.get_domain_age(domain, timeout=5)
    ssl_info = check_ssl_certificate(url, timeout=5)

    score_data = calculate_composite_score(
        domain_age_years=domain_info.get("domain_age_years"),
        ssl_valid=ssl_info.get("valid"),
        ssl_days_remaining=ssl_info.get("days_until_expiry", 0),
        ssl_issuer=ssl_info.get("issuer", "")
    )

    return {
        "url": url,
        "domain": domain,
        "domain_age_years": domain_info.get("domain_age_years"),
        "ssl_valid": ssl_info.get("valid"),
        "score": score_data["composite_score"],
        "trust_level": score_data["trust_level"],
    }


# Initialize
whois_checker = WhoisChecker()
app = Flask(__name__)
CORS(app)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Redis cache setup (optional, fallback to in-memory if not available)
try:
    cache = redis.Redis(
        host='localhost', port=6379, decode_responses=True
    )
    cache.ping()
    CACHE_ENABLED = True
except Exception:
    logger.warning("Redis not available, using in-memory cache")
    cache = {}
    CACHE_ENABLED = False


# ===========================
# Cache Functions
# ===========================

def get_cache_key(url: str) -> str:
    """Generate a cache key for the URL using SHA-256."""
    return f"site_check:{hashlib.sha256(url.encode()).hexdigest()}"


def get_from_cache(key: str):
    """Get data from cache."""
    if CACHE_ENABLED:
        data = cache.get(key)
        return json.loads(data) if data else None
    else:
        return cache.get(key)


def set_in_cache(key: str, data, ttl: int = 604800):
    """Set data in cache (default TTL: 7 days)."""
    if CACHE_ENABLED:
        cache.setex(key, ttl, json.dumps(data))
    else:
        cache[key] = data


# ===========================
# SSRF Protection
# ===========================

ALLOWED_SCHEMES = ("http", "https")
DOMAIN_ALLOWLIST = set()  # Add domains here to restrict access


def is_ip_private(ip_str: str) -> bool:
    """Return True if IP is private/loopback/reserved/etc."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except Exception:
        # Be conservative: if we can't parse the IP, treat as private
        return True


def resolve_hostname(hostname: str) -> list:
    """Resolve hostname to IPs. Return empty list on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        addrs = {info[4][0] for info in infos}
        return list(addrs)
    except Exception:
        return []


def is_url_allowed(url: str) -> tuple:
    """
    Validate URL for outbound fetching.
    Returns (allowed: bool, reason_or_ok: str).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid_url"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"bad_scheme:{parsed.scheme}"

    host = parsed.hostname
    if not host:
        return False, "no_host"

    # If domain allowlist is active, require host to be there
    if DOMAIN_ALLOWLIST:
        normalized_host = host.lower().rstrip(".")
        allowed_domains = {
            d.lower().rstrip(".") for d in DOMAIN_ALLOWLIST
        }
        if normalized_host not in allowed_domains:
            return False, "not_in_allowlist"

    # Resolve and verify IPs are not private/reserved
    addrs = resolve_hostname(host)
    if not addrs:
        return False, "dns_resolution_failed"

    for addr in addrs:
        if is_ip_private(addr):
            return False, f"resolved_to_private_ip:{addr}"

    return True, "ok"


def safe_requests_head(url: str, timeout: int = 3) -> dict:
    """
    Use HEAD (or GET fallback) to obtain headers/status safely.
    Raises ValueError for disallowed URLs; returns dict on success.
    """
    allowed, reason = is_url_allowed(url)
    if not allowed:
        raise ValueError(f"URL NOT ALLOWED: {reason}")

    headers = {
        "User-Agent": "SiteOrigin-Checker/1.0 (+https://example.com)",
    }

    try:
        resp = requests.head(
            url, headers=headers, allow_redirects=False, timeout=timeout
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers)
        }
    except requests.exceptions.RequestException:
        # Try GET as last resort (some servers don't support HEAD)
        try:
            resp = requests.get(
                url, headers=headers, allow_redirects=False,
                timeout=timeout, stream=True
            )
            resp.close()
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers)
            }
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"request_failed: {str(e)}")


# ===========================
# Safe Wrapper Functions
# ===========================

def safe_get_domain_age(domain: str) -> dict:
    """
    Return dict with creation_date and domain_age_years.
    If whois_checker fails, return safe defaults.
    """
    try:
        info = whois_checker.get_domain_age(domain)
        if not info:
            return {"creation_date": None, "domain_age_years": 0}

        if isinstance(info, dict):
            return {
                "creation_date": info.get("creation_date"),
                "domain_age_years": info.get("domain_age_years", 0),
            }

        if isinstance(info, (list, tuple)) and len(info) >= 2:
            return {
                "creation_date": info[0],
                "domain_age_years": info[1] or 0
            }

        return {"creation_date": None, "domain_age_years": 0}
    except Exception as e:
        logger.warning(f"safe_get_domain_age error for {domain}: {e}")
        return {"creation_date": None, "domain_age_years": 0}


def safe_check_ssl(url: str) -> dict:
    """
    Call check_ssl_certificate but ensure it never returns None
    and will not attempt requests to disallowed URLs.
    """
    try:
        allowed, reason = is_url_allowed(url)
        if not allowed:
            return {
                "valid": False,
                "issuer": None,
                "expiry_date": None,
                "days_until_expiry": 0,
                "note": reason
            }

        ssl_info = check_ssl_certificate(url, timeout=5)
        if not ssl_info:
            return {
                "valid": False,
                "issuer": None,
                "expiry_date": None,
                "days_until_expiry": 0
            }

        is_dict = isinstance(ssl_info, dict)
        return {
            "valid": (
                ssl_info.get("valid", False)
                if is_dict else bool(ssl_info)
            ),
            "issuer": (
                ssl_info.get("issuer") if is_dict else None
            ),
            "expiry_date": (
                ssl_info.get("expiry_date") if is_dict else None
            ),
            "days_until_expiry": (
                ssl_info.get("days_until_expiry", 0)
                if is_dict else 0
            ),
        }
    except Exception as e:
        logger.warning(f"safe_check_ssl error for {url}: {e}")
        return {
            "valid": False,
            "issuer": None,
            "expiry_date": None,
            "days_until_expiry": 0
        }


def safe_calculate_composite_score(**kwargs):
    """
    Call calculate_composite_score flexibly.
    Returns dict with composite_score and trust_level.
    """
    try:
        sig = inspect.signature(calculate_composite_score)
        call_kwargs = {}

        for name in sig.parameters:
            if name in kwargs:
                call_kwargs[name] = kwargs[name]

        if not call_kwargs:
            # Try common fallback mappings
            fallback_map = {
                "domain_age_years": kwargs.get("domain_age_years"),
                "ssl_valid": kwargs.get("ssl_valid"),
                "ssl_days_remaining": kwargs.get("ssl_days_remaining"),
                "ssl_issuer": kwargs.get("ssl_issuer"),
            }
            call_kwargs = {
                k: v for k, v in fallback_map.items() if v is not None
            }

        if call_kwargs:
            result = calculate_composite_score(**call_kwargs)
        else:
            result = calculate_composite_score()

        if not isinstance(result, dict):
            return {
                "composite_score": 0,
                "trust_level": "unknown",
                "details": str(result)
            }

        return result
    except Exception as e:
        logger.warning(f"safe_calculate_composite_score error: {e}")
        return {
            "composite_score": 0,
            "trust_level": "error",
            "details": str(e)
        }


# ===========================
# Routes
# ===========================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy"}), 200


@app.route("/check", methods=["POST"])
def check_site():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Check cache first
        cache_key = get_cache_key(url)
        cached_result = get_from_cache(cache_key)
        if cached_result:
            logger.info(f"Cache hit for {url}")
            return jsonify(cached_result), 200

        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path

        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]

        # Domain info safely
        domain_info = safe_get_domain_age(domain)
        domain_creation_date = domain_info.get("creation_date")
        domain_age_years = domain_info.get("domain_age_years", 0)

        # SSL info safely
        ssl_info = safe_check_ssl(url)

        # Calculate composite score safely
        score_data = safe_calculate_composite_score(
            domain_age_years=domain_age_years,
            ssl_valid=ssl_info.get("valid", False),
            ssl_days_remaining=ssl_info.get("days_until_expiry", 0),
            ssl_issuer=ssl_info.get("issuer", "")
        )

        # Prepare response
        response_data = {
            "url": url,
            "domain": domain,
            "domain_age_years": domain_age_years,
            "domain_creation_date": (
                domain_creation_date.isoformat()
                if (hasattr(domain_creation_date, "isoformat")
                    and domain_creation_date)
                else None
            ),
            "ssl_valid": ssl_info.get("valid", False),
            "ssl_issuer": ssl_info.get("issuer"),
            "ssl_expiry": ssl_info.get("expiry_date"),
            "ssl_days_remaining": ssl_info.get("days_until_expiry"),
            "score": score_data.get('composite_score', 0),
            "score_details": score_data,
            "trust_level": score_data.get('trust_level', 'unknown'),
            "checked_at": datetime.now().isoformat()
        }

        # Cache the result
        set_in_cache(cache_key, response_data)
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f"Error checking site: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/batch-check', methods=['POST'])
def batch_check_sites():
    """
    Check multiple sites at once.
    Request body: {"urls": ["https://example1.com"]}
    """
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({"error": "URLs array is required"}), 400

        urls = data['urls'][:10]  # Limit to 10 URLs per request
        results = []

        for url in urls:
            try:
                # Validate URL before any work
                allowed, reason = is_url_allowed(url)
                if not allowed:
                    results.append({
                        "url": url,
                        "error": "URL not allowed",
                        "reason": reason,
                        "score": 0,
                        "trust_level": "blocked"
                    })
                    continue

                # Check cache first
                cache_key = get_cache_key(url)
                cached_result = get_from_cache(cache_key)
                if cached_result:
                    results.append(cached_result)
                    continue

                # Process URL
                parsed_url = urlparse(url)
                domain = parsed_url.netloc or parsed_url.path
                if domain.startswith('www.'):
                    domain = domain[4:]

                domain_info = safe_get_domain_age(domain)
                domain_age_years = domain_info.get("domain_age_years", 0)

                ssl_info = safe_check_ssl(url)
                score_data = safe_calculate_composite_score(
                    domain_age_years=domain_age_years,
                    ssl_valid=ssl_info.get("valid", False),
                    ssl_days_remaining=ssl_info.get(
                        "days_until_expiry", 0
                    ),
                    ssl_issuer=ssl_info.get("issuer", "")
                )

                result = {
                    "url": url,
                    "domain": domain,
                    "domain_age_years": domain_age_years,
                    "ssl_valid": ssl_info.get("valid", False),
                    "score": score_data.get('composite_score', 0),
                    "trust_level": score_data.get(
                        'trust_level', 'unknown'
                    )
                }

                # Cache the result (1 day for batch results)
                set_in_cache(cache_key, result, ttl=86400)
                results.append(result)

            except Exception as e:
                logger.error(f"Error checking {url}: {str(e)}")
                results.append({
                    "url": url,
                    "error": str(e),
                    "score": 0,
                    "trust_level": "error"
                })

        return jsonify({"results": results}), 200

    except Exception as e:
        logger.error(f"Error in batch check: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ===========================
# Application Entry Point
# ===========================

if __name__ == '__main__':
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower()
    debug_mode = debug_mode == "true"
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=debug_mode, port=port)
