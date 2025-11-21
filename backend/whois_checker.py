#!/usr/bin/env python3
"""
WHOIS Checker Module
Handles domain age calculation and WHOIS data retrieval
"""

import whois
import requests
import os
from datetime import datetime, date
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from . import _env  # noqa: F401

logger = logging.getLogger(__name__)


class WhoisChecker:
    """Main class for checking WHOIS information"""

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        # Per-call flags
        self._who_dat_rate_limited = False
        self._who_dat_failed = False
        self._rdap_failed = False
        # Track timeouts separately from other request failures
        self._who_dat_timeout = False
        self._rdap_timeout = False
        self._whoisxml_failed = False
        self._whoisxml_timeout = False
        self._last_registrar: Optional[str] = None

    def get_domain_age(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain age information.
        Returns dict with:
            - domain_age_years
            - creation_date (ISO string)
            - registrar

        Returns None if unavailable. In case external APIs both fail, an
        explicit error dict is returned so tests can assert that path.
        """
        domain = self._normalize_domain(domain)

        # Cache
        if domain in self._cache:
            return self._cache[domain]

        # Reset flags for this call
        self._who_dat_rate_limited = False
        self._who_dat_failed = False
        self._rdap_failed = False
        self._last_registrar = None

        creation_date: Optional[datetime] = None
        result: Optional[Dict[str, Any]] = None

        try:
            creation_date = self._try_who_dat(domain)
            if not creation_date:
                creation_date = self._try_rdap(domain)

            # Try python-whois as fallback if external APIs fail
            if not creation_date:
                creation_date = self._try_python_whois(domain)

            # Final fallback: WhoisXMLAPI (requires WHOISXML_API_KEY)
            if not creation_date:
                creation_date = self._try_whoisxml(domain)

            if creation_date:
                age_years = calculate_domain_age(creation_date)
                result = {
                    "domain_age_years": age_years,
                    "creation_date": creation_date.isoformat(),
                    "registrar": None,
                }

                # Prefer registrar captured from APIs
                if self._last_registrar:
                    result["registrar"] = self._last_registrar
                else:
                    reg = self._get_registrar(domain)
                    if reg:
                        result["registrar"] = reg

                self._cache[domain] = result

        except Exception:  # pragma: no cover - defensive
            logger.exception(
                "Unexpected error in get_domain_age for %s", domain
            )

        # If who-dat was rate-limited, prefer returning None so
        # callers/tests can treat it as temporarily unavailable.
        if self._who_dat_rate_limited and not result:
            return None

        # If both attempts timed out, return None (network issues)
        if self._who_dat_timeout and self._rdap_timeout and not result:
            return None

        # If both external lookups failed (non-timeout failures), return
        # an explicit error dict for tests that assert that path.
        if self._who_dat_failed and self._rdap_failed and not result:
            return {"domain_age_years": 0, "error": "whois_unavailable"}

        return result

    def _try_who_dat(self, domain: str) -> Optional[datetime]:
        """Query who-dat API for creation date and registrar."""
        try:
            url = f"https://who-dat.as93.net/{domain}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 429:
                self._who_dat_rate_limited = True
                return None
            if resp.status_code != 200:
                self._who_dat_failed = True
                return None

            data = resp.json()
            if isinstance(data, dict) and data.get("registrar"):
                self._last_registrar = data.get("registrar")

            # possible fields containing creation date
            keys = (
                "creation_date", "created", "registered", "registration"
            )
            for key in keys:
                if key in data and data[key]:
                    cd = parse_creation_date(str(data[key]))
                    if cd:
                        return cd

            return None

        except requests.Timeout:
            self._who_dat_timeout = True
            self._who_dat_failed = True
            return None
        except requests.RequestException:
            self._who_dat_failed = True
            return None

    def _try_rdap(self, domain: str) -> Optional[datetime]:
        """Query RDAP endpoints for creation date and registrar."""
        try:
            url = f"https://rdap.org/domain/{domain}"
            # FIXED: Follow redirects automatically
            resp = requests.get(url, timeout=5, allow_redirects=True)
            if resp.status_code != 200:
                self._rdap_failed = True
                return None

            data = resp.json()
            if isinstance(data, dict) and data.get("registrar"):
                self._last_registrar = data.get("registrar")

            # RDAP often uses events
            events = data.get("events") or []
            for ev in events:
                if ev.get("eventAction") == "registration":
                    date_str = ev.get("eventDate")
                    if date_str:
                        cd = parse_creation_date(str(date_str))
                        if cd:
                            return cd

            return None

        except requests.Timeout:
            self._rdap_timeout = True
            self._rdap_failed = True
            return None
        except requests.RequestException:
            self._rdap_failed = True
            return None

    def _try_python_whois(self, domain: str) -> Optional[datetime]:
        try:
            w = whois.whois(domain)
            if not w:
                return None
            creation_date = getattr(w, "creation_date", None)
            if isinstance(creation_date, list) and creation_date:
                creation_date = creation_date[0]

            # Normalize common types: datetime, date, or string
            if isinstance(creation_date, datetime):
                return creation_date
            if isinstance(creation_date, date):
                # convert date to datetime at midnight
                return datetime(
                    creation_date.year,
                    creation_date.month,
                    creation_date.day,
                )
            if isinstance(creation_date, str):
                parsed = parse_creation_date(creation_date)
                if parsed:
                    return parsed
        except Exception:
            return None
        return None

    def _get_registrar(self, domain: str) -> Optional[str]:
        try:
            w = whois.whois(domain)
            registrar = getattr(w, "registrar", None)
            return registrar
        except Exception:
            return None

    def _try_whoisxml(self, domain: str) -> Optional[datetime]:
        """Query WhoisXMLAPI as final fallback.

        Requires environment variable `WHOISXML_API_KEY` to be set.
        Returns a datetime on success or None on failure.
        """
        # Ensure environment variables from .env are loaded and read
        # (load_dotenv() at module import ensures this in most cases,
        # but we also guard here).
        api_key = os.environ.get("WHOISXML_API_KEY")
        if not api_key:
            logger.debug(
                "WHOISXML_API_KEY not set; skipping WhoisXML fallback"
            )
            return None

        try:
            base_url = (
                "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            )
            params = (
                f"?apiKey={api_key}&domainName={domain}"
                f"&outputFormat=JSON"
            )
            url = base_url + params
            resp = requests.get(url, timeout=6)
            if resp.status_code != 200:
                self._whoisxml_failed = True
                return None

            data = resp.json()
            # Typical structure:
            # { 'WhoisRecord': { 'createdDate': '...',
            #   'registryData': {...}, 'registrarName': '...' } }
            record = data.get("WhoisRecord") or {}

            # Try several possible locations for creation date
            for key in ("createdDate", "createdDateNormalized", "created"):
                cd = record.get(key)
                if cd:
                    parsed = parse_creation_date(str(cd))
                    if parsed:
                        # try to capture registrar
                        registry = record.get("registryData", {})
                        registrar = (
                            record.get("registrarName")
                            or registry.get("registrarName")
                        )
                        if registrar:
                            self._last_registrar = registrar
                        return parsed

            # Also inspect nested registryData
            registry = record.get("registryData") or {}
            cd = (
                registry.get("createdDate")
                or registry.get("createdDateNormalized")
            )
            if cd:
                parsed = parse_creation_date(str(cd))
                if parsed:
                    registrar = registry.get("registrarName")
                    if registrar:
                        self._last_registrar = registrar
                    return parsed

            return None
        except requests.Timeout:
            self._whoisxml_timeout = True
            self._whoisxml_failed = True
            return None
        except requests.RequestException:
            self._whoisxml_failed = True
            return None

    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain by:
        1. Removing protocol (http/https)
        2. Removing www prefix
        3. Extracting base domain from subdomain
        """
        if not domain:
            return domain

        d = domain.strip().lower()

        # Remove protocol
        if d.startswith(("http://", "https://")):
            d = urlparse(d).netloc

        # Remove www prefix
        if d.startswith("www."):
            d = d[4:]

        # Extract base domain from subdomain
        d = self._extract_base_domain(d)

        return d

    def _extract_base_domain(self, domain: str) -> str:
        """
        Extract the base/root domain from a subdomain.
        Examples:
        - blog.example.com -> example.com
        - shop.example.co.uk -> example.co.uk
        - example.com -> example.com
        """
        # Try using tldextract library if available
        try:
            import tldextract  # type: ignore[reportMissingImports]
            extracted = tldextract.extract(domain)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            return domain
        except ImportError:
            # Fallback: Simple heuristic for common TLDs
            # This handles most cases but may not work for all TLDs
            parts = domain.split('.')

            # Handle multi-part TLDs like .co.uk, .com.au, etc.
            known_double_tlds = [
                'co.uk', 'com.au', 'co.jp', 'co.in', 'co.za',
                'com.br', 'com.cn', 'com.mx', 'com.ar', 'com.co',
                'net.au', 'org.uk', 'ac.uk', 'gov.uk', 'sch.uk'
            ]

            if len(parts) >= 3:
                # Check if last two parts form a known double TLD
                potential_double_tld = '.'.join(parts[-2:])
                if potential_double_tld in known_double_tlds:
                    # Return domain.multi-part-tld (e.g., example.co.uk)
                    if len(parts) >= 3:
                        return '.'.join(parts[-3:])
                    else:
                        return domain
                else:
                    # Return domain.tld (e.g., example.com)
                    return '.'.join(parts[-2:])

            # If 2 or fewer parts, return as-is
            return domain


def calculate_domain_age(creation_date: datetime) -> float:
    """Calculate domain age in years from creation date."""
    if not creation_date or not isinstance(creation_date, datetime):
        return None
    now = datetime.now()
    if creation_date > now:
        return 0.0
    delta = now - creation_date
    return round(delta.days / 365.25, 2)


def parse_creation_date(date_str: str) -> Optional[datetime]:
    if not date_str or not isinstance(date_str, str):
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%m/%d/%Y",
        "%Y.%m.%d",
        "%d/%m/%Y",
        "%d-%b-%Y",
        "%Y-%m-%dT%H:%M:%S%z",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            # Expected - date doesn't match this format, try next
            continue
    try:
        from dateutil import parser

        return parser.parse(date_str)
    except (ImportError, ValueError) as e:
        logger.debug("Failed to parse creation date using dateutil: %s (%s)", date_str, e)
        return None
