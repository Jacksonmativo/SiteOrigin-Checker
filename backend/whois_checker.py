#!/usr/bin/env python3
"""
WHOIS Checker Module
Handles domain age calculation and WHOIS data retrieval
"""

import whois
import requests
from datetime import datetime
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WhoisChecker:
    """Main class for checking WHOIS information"""

    def __init__(self):
        self._cache = {}

    def get_domain_age(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain age information
        Returns dict with domain_age_years, registrar, and other info
        """
        # Normalize domain
        domain = self._normalize_domain(domain)

        # Check cache first
        if domain in self._cache:
            return self._cache[domain]

        result = None
        creation_date = None

        try:
            # Try who-dat API FIRST (so tests can mock it)
            creation_date = self._try_who_dat(domain)

            # Fallback to RDAP
            if not creation_date:
                creation_date = self._try_rdap(domain)

            # Fallback to python-whois
            if not creation_date:
                creation_date = self._try_python_whois(domain)

            if creation_date:
                age_years = calculate_domain_age(creation_date)
                result = {
                    "domain_age_years": age_years,
                    "creation_date": (
                        creation_date.isoformat() if creation_date else None
                    ),
                    "registrar": self._get_registrar(domain),
                }

                # Cache the result
                self._cache[domain] = result

        except Exception as e:
            logger.error(f"Error getting domain age for {domain}: {str(e)}")

        return result

    def _try_who_dat(self, domain: str) -> Optional[datetime]:
        """Try to get domain info using who-dat API"""
        try:
            url = f"https://who-dat.as93.net/{domain}"
            response = requests.get(url, timeout=5)

            if response.status_code == 429:
                logger.warning("Rate limited by who-dat API")
                return None

            if response.status_code == 200:
                data = response.json()

                # Check for creation date in various fields
                date_fields = [
                    "creation_date",
                    "created",
                    "registered",
                    "registration"]
                for field in date_fields:
                    if field in data and data[field]:
                        creation_date = parse_creation_date(data[field])
                        if creation_date:
                            logger.info(
                                f"Got creation date from who-dat for {domain}")
                            return creation_date

        except requests.Timeout:
            logger.warning(f"Timeout connecting to who-dat for {domain}")
            return None
        except requests.RequestException as e:
            logger.debug(f"who-dat failed for {domain}: {str(e)}")
            return None

        return None

    def _try_rdap(self, domain: str) -> Optional[datetime]:
        """Try to get domain info using RDAP"""
        try:
            url = f"https://rdap.net/domain/{domain}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()

                # Look for registration date in events
                if "events" in data:
                    for event in data["events"]:
                        if event.get("eventAction") == "registration":
                            date_str = event.get("eventDate")
                            if date_str:
                                creation_date = parse_creation_date(date_str)
                                if creation_date:
                                    logger.info(
                                        f"Got creation date from RDAP for "
                                        f"{domain}"
                                    )
                                    return creation_date

        except Exception as e:
            logger.debug(f"RDAP failed for {domain}: {str(e)}")

        return None

    def _try_python_whois(self, domain: str) -> Optional[datetime]:
        """Try to get domain info using python-whois"""
        try:
            w = whois.whois(domain)
            if w and w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                logger.info(
                    f"Got creation date from python-whois for {domain}")
                return creation_date
        except Exception as e:
            logger.debug(f"python-whois failed for {domain}: {str(e)}")

        return None

    def _get_registrar(self, domain: str) -> Optional[str]:
        """Get domain registrar information"""
        try:
            w = whois.whois(domain)
            if w and w.registrar:
                return w.registrar
        except Exception as e:
            logger.debug(f"Could not get registrar for {domain}: {str(e)}")

        return None

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name"""
        if not domain:
            return domain

        domain = domain.lower().strip()

        # Remove protocol
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc

        # Remove www.
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        if not domain or len(domain) > 255:
            return False

        # Check for invalid characters
        if " " in domain or ".." in domain:
            return False

        # Check for protocol (should not have it)
        if domain.startswith(("http://", "https://")):
            return False

        # Basic format check
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        return True

    def get_multiple_domain_ages(self, domains: list) -> Dict[str, Any]:
        """Process multiple domains"""
        results = {}
        for domain in domains:
            results[domain] = self.get_domain_age(domain)
        return results


def calculate_domain_age(creation_date: datetime) -> float:
    """
    Calculate domain age in years from creation date
    Returns 0 for future dates
    """
    if not creation_date:
        return None

    if not isinstance(creation_date, datetime):
        return None

    now = datetime.now()

    # Handle future dates
    if creation_date > now:
        return 0.0

    age_delta = now - creation_date
    age_years = age_delta.days / 365.25

    return round(age_years, 2)


def parse_creation_date(date_str: str) -> Optional[datetime]:
    """
    Parse various date string formats
    Returns None if parsing fails
    """
    if not date_str or not isinstance(date_str, str):
        return None

    # Common date formats in WHOIS/RDAP responses
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
            continue

    # Try parsing with dateutil if available
    try:
        from dateutil import parser
        return parser.parse(date_str)
    except Exception as e:
        logging.warning(f"WHOIS parse failed for date '{date_str}': {e}")
        return None
