#!/usr/bin/env python3
"""
Score Calculator Module
Calculates composite authenticity scores for website analysis
Now includes cipher and DNS scoring
"""

from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ScoreCalculator:
    """Main class for calculating composite trust scores"""

    def __init__(
        self,
        domain_weight: float = 0.6,
        ssl_weight: float = 0.4,
        cipher_weight: float = 0.0,
        dns_weight: float = 0.0,
    ):
        """
        Initialize score calculator with custom weights

        Args:
            domain_weight: Weight for domain age score (default 0.6)
            ssl_weight: Weight for SSL score (default 0.4)
            cipher_weight: Weight for cipher score (default 0.0)
            dns_weight: Weight for DNS score (default 0.0)
        """
        self.domain_weight = domain_weight
        self.ssl_weight = ssl_weight
        self.cipher_weight = cipher_weight
        self.dns_weight = dns_weight

        # Ensure weights sum to 1.0
        total_weight = (
            domain_weight + ssl_weight + cipher_weight + dns_weight
        )
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(
                f"Weights sum to {total_weight}, not 1.0. "
                "Consider adjusting weights."
            )

    def calculate_score(
        self,
        domain_data: Dict[str, Any],
        ssl_data: Dict[str, Any],
        cipher_data: Dict[str, Any] = None,
        dns_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate composite score from domain, SSL, cipher, and DNS data

        Args:
            domain_data: Dict with 'domain_age_years' key
            ssl_data: Dict with SSL certificate information
            cipher_data: Dict with cipher suite information (optional)
            dns_data: Dict with DNS record information (optional)

        Returns:
            Dict with composite_score, individual scores, trust_level
        """
        # Extract domain age
        domain_age_years = domain_data.get("domain_age_years")

        # Calculate individual scores
        domain_score = calculate_domain_age_score(domain_age_years)
        ssl_score = calculate_ssl_score(ssl_data)
        cipher_score = (
            calculate_cipher_score(cipher_data)
            if cipher_data else 50.0
        )
        dns_score = (
            calculate_dns_score(dns_data)
            if dns_data else 50.0
        )

        # Calculate composite score with weights
        composite = calculate_weighted_composite_score(
            domain_score,
            ssl_score,
            cipher_score,
            dns_score,
            self.domain_weight,
            self.ssl_weight,
            self.cipher_weight,
            self.dns_weight
        )

        # Determine trust level
        trust_level = self._get_trust_level(composite)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            composite,
            domain_age_years,
            ssl_data,
            cipher_data,
            dns_data
        )

        return {
            "composite_score": round(composite, 1),
            "domain_score": round(domain_score, 1),
            "ssl_score": round(ssl_score, 1),
            "cipher_score": round(cipher_score, 1),
            "dns_score": round(dns_score, 1),
            "trust_level": trust_level,
            "weights": {
                "domain": self.domain_weight,
                "ssl": self.ssl_weight,
                "cipher": self.cipher_weight,
                "dns": self.dns_weight
            },
            "recommendations": recommendations,
        }

    def _get_trust_level(self, score: float) -> str:
        """Determine trust level from score"""
        if score >= 80:
            return "high"
        elif score >= 60:
            return "medium"
        else:
            return "low"

    def _generate_recommendations(
        self,
        score: float,
        domain_age: Optional[float],
        ssl_data: Dict[str, Any],
        cipher_data: Optional[Dict[str, Any]],
        dns_data: Optional[Dict[str, Any]]
    ) -> list:
        """Generate recommendations based on score and data"""
        recommendations = []

        if score >= 80:
            recommendations.append("This appears to be a trustworthy site")
        elif score >= 60:
            recommendations.append("Exercise normal caution when interacting")
        else:
            recommendations.append(
                "Exercise caution when providing sensitive information"
            )

        # Domain-specific recommendations
        if domain_age is not None and domain_age < 1:
            recommendations.append(
                "Domain is relatively new - verify legitimacy"
            )

        # SSL-specific recommendations
        if not ssl_data.get("is_valid") and not ssl_data.get("valid"):
            recommendations.append(
                "SSL certificate is invalid - avoid entering sensitive data"
            )
        elif ssl_data.get("expiring_soon"):
            recommendations.append("SSL certificate expiring soon")

        # Cipher-specific recommendations
        if cipher_data:
            if cipher_data.get("cipher_strength") == "weak":
                recommendations.append(
                    "Weak encryption detected - site may be vulnerable"
                )
            elif cipher_data.get("weak_ciphers_found"):
                recommendations.append(
                    "Site supports some weak cipher suites"
                )

        # DNS-specific recommendations
        if dns_data:
            if dns_data.get("dns_score", 1.0) < 0.5:
                recommendations.append(
                    "DNS configuration incomplete - verify site authenticity"
                )
            if not dns_data.get("spf_record"):
                recommendations.append(
                    "No SPF record - email security may be compromised"
                )

        return recommendations


def calculate_domain_age_score(age_years: Optional[float]) -> float:
    """
    Calculate score based on domain age

    Scoring:
    - >5 years: 100
    - 3-5 years: 70
    - 1-3 years: 50
    - <1 year: 20
    - Unknown/negative: 20
    """
    if age_years is None or age_years < 0:
        return 20

    if age_years >= 5:
        return 100
    elif age_years >= 3:
        return 70
    elif age_years >= 1:
        return 50
    else:
        return 20


def calculate_ssl_score(ssl_data: Dict[str, Any]) -> float:
    """
    Calculate score based on SSL certificate data

    Args:
        ssl_data: Dict with keys:
            - is_valid/valid: bool
            - cipher_strength: str ('strong', 'medium', 'weak')
            - expiring_soon: bool
            - days_until_expiry: int

    Returns:
        Score from 0-100
    """
    if not ssl_data:
        return 0

    # Check validity (support both 'is_valid' and 'valid' keys)
    is_valid = ssl_data.get("is_valid", ssl_data.get("valid", False))
    if not is_valid:
        return 0

    # Base score for valid certificate
    score = 100

    # Check cipher strength
    cipher_strength = ssl_data.get("cipher_strength", "").lower()
    if cipher_strength == "weak":
        score = 70
    elif cipher_strength == "medium":
        score = 70
    # 'strong' stays at 100

    # Check expiration
    expiring_soon = ssl_data.get("expiring_soon", False)
    days_until_expiry = ssl_data.get("days_until_expiry")

    if expiring_soon:
        score = min(score, 50)
    elif days_until_expiry is not None:
        if days_until_expiry < 30:
            score = min(score, 70)

    return score


def calculate_cipher_score(cipher_data: Dict[str, Any]) -> float:
    """
    Calculate score based on cipher suite analysis

    Args:
        cipher_data: Dict with:
            - cipher_score: float (0.0-1.0) from cipher_checker
            - cipher_strength: str ('strong', 'medium', 'weak')
            - protocol_version: str (TLS version)
            - weak_ciphers_found: list

    Returns:
        Score from 0-100
    """
    if not cipher_data:
        return 50  # Neutral score if no data

    # Use the normalized score from cipher_checker (0.0-1.0)
    cipher_score = cipher_data.get("cipher_score", 0.5)

    # Convert to 0-100 scale
    score = cipher_score * 100

    # Additional penalties
    weak_ciphers = cipher_data.get("weak_ciphers_found", [])
    if len(weak_ciphers) > 0:
        # Penalty for each weak cipher found
        penalty = min(30, len(weak_ciphers) * 10)
        score -= penalty

    # Ensure score stays in valid range
    score = max(0, min(100, score))

    return score


def calculate_dns_score(dns_data: Dict[str, Any]) -> float:
    """
    Calculate score based on DNS records

    Args:
        dns_data: Dict with:
            - dns_score: float (0.0-1.0) from dns_checker
            - dns_reliability: str
            - a_records, mx_records, ns_records: lists
            - spf_record, dmarc_record: str or None

    Returns:
        Score from 0-100
    """
    if not dns_data:
        return 50  # Neutral score if no data

    # Use the normalized score from dns_checker (0.0-1.0)
    dns_score = dns_data.get("dns_score", 0.5)

    # Convert to 0-100 scale
    score = dns_score * 100

    # Ensure score stays in valid range
    score = max(0, min(100, score))

    return score


def calculate_weighted_composite_score(
    domain_score: float,
    ssl_score: float,
    cipher_score: float = 50.0,
    dns_score: float = 50.0,
    domain_weight: float = 0.35,
    ssl_weight: float = 0.25,
    cipher_weight: float = 0.20,
    dns_weight: float = 0.20,
) -> float:
    """
    Calculate weighted composite score

    Args:
        domain_score: Domain age score (0-100)
        ssl_score: SSL security score (0-100)
        cipher_score: Cipher suite score (0-100)
        dns_score: DNS configuration score (0-100)
        domain_weight: Weight for domain score (default 0.35)
        ssl_weight: Weight for SSL score (default 0.25)
        cipher_weight: Weight for cipher score (default 0.20)
        dns_weight: Weight for DNS score (default 0.20)

    Returns:
        Composite score (0-100)
    """
    composite = (
        (domain_score * domain_weight) +
        (ssl_score * ssl_weight) +
        (cipher_score * cipher_weight) +
        (dns_score * dns_weight)
    )
    return round(composite, 1)


def calculate_composite_score(
    domain_age_years: Optional[float] = None,
    ssl_valid: bool | float = False,
    ssl_days_remaining: int | float = 0,
    ssl_issuer: str = "",
    cipher_score: float = 0.5,
    dns_score: float = 0.5,
) -> Any:
    """
    Calculate composite score from raw parameters
    This is the function called by app.py

    Args:
        domain_age_years: Age of domain in years
        ssl_valid: Whether SSL certificate is valid
        ssl_days_remaining: Days until SSL expiry
        ssl_issuer: SSL certificate issuer
        cipher_score: Cipher strength score (0.0-1.0)
        dns_score: DNS reliability score (0.0-1.0)

    Returns:
        Dict with composite_score, trust_level, and details
    """
    try:
        # Legacy numeric signature handling.
        # Some older callers pass numeric domain and SSL scores as the first
        # two positional args. Detect that shape (numeric, non-bool) and
        # return a numeric composite for backward compatibility.
        def _is_numeric_nonbool(x):
            return isinstance(x, (int, float)) and not isinstance(x, bool)

        if (
            _is_numeric_nonbool(domain_age_years)
            and _is_numeric_nonbool(ssl_valid)
        ):
            domain_score_val = float(domain_age_years)
            ssl_score_val = float(ssl_valid)

            # Optional weights passed as positional args in third/fourth params
            domain_weight = 0.6
            ssl_weight = 0.4
            # Only treat the 3rd/4th positional args as weights when they are
            # strictly between 0 and 1 (exclusive of 0). This avoids
            # confusing default zeros with intended weight values.
            if (
                isinstance(ssl_days_remaining, (int, float))
                and 0 < ssl_days_remaining <= 1
            ):
                domain_weight = float(ssl_days_remaining)

            if (
                isinstance(ssl_issuer, (int, float))
                and 0 < ssl_issuer <= 1
            ):
                ssl_weight = float(ssl_issuer)

            composite_num = (domain_score_val * domain_weight) + (
                ssl_score_val * ssl_weight
            )
            return composite_num

        # Calculate domain score
        domain_score = calculate_domain_age_score(domain_age_years)

        # Build SSL data dict
        ssl_data = {
            "valid": ssl_valid,
            "is_valid": ssl_valid,
            "days_until_expiry": ssl_days_remaining,
            "expiring_soon": (
                ssl_days_remaining < 30
                if ssl_days_remaining is not None
                else False
            ),
            "issuer": ssl_issuer
        }

        # Calculate SSL score
        ssl_score_val = calculate_ssl_score(ssl_data)

        # Convert normalized scores (0.0-1.0) to 0-100 scale
        cipher_score_val = cipher_score * 100
        dns_score_val = dns_score * 100

        # Calculate weighted composite
        composite = calculate_weighted_composite_score(
            domain_score,
            ssl_score_val,
            cipher_score_val,
            dns_score_val
        )

        # Determine trust level
        if composite >= 80:
            trust_level = "high"
        elif composite >= 60:
            trust_level = "medium"
        else:
            trust_level = "low"

        # Legacy numeric style: first two args are numbers.
        # Return numeric composite for backward-compatibility.
        if (
            isinstance(ssl_valid, (int, float))
            and not isinstance(ssl_valid, bool)
        ):
            return composite

        return {
            "composite_score": composite,
            "domain_score": domain_score,
            "ssl_score": ssl_score_val,
            "cipher_score": cipher_score_val,
            "dns_score": dns_score_val,
            "trust_level": trust_level,
            "details": {
                "domain_age_years": domain_age_years,
                "ssl_valid": ssl_valid,
                "ssl_days_remaining": ssl_days_remaining,
                "cipher_score_normalized": cipher_score,
                "dns_score_normalized": dns_score,
            },
        }
    except Exception as e:
        logger.error(f"Error calculating composite score: {e}")
        return {
            "composite_score": 0,
            "trust_level": "error",
            "details": str(e)
        }
