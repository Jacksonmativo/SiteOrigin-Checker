#!/usr/bin/env python3
"""
Score Calculator Module
Calculates composite authenticity scores for website analysis
"""

from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ScoreCalculator:
    """Main class for calculating composite trust scores"""

    def __init__(self, domain_weight: float = 0.6, ssl_weight: float = 0.4):
        """
        Initialize score calculator with custom weights

        Args:
            domain_weight: Weight for domain age score (default 0.6)
            ssl_weight: Weight for SSL score (default 0.4)
        """
        self.domain_weight = domain_weight
        self.ssl_weight = ssl_weight

    def calculate_score(
        self, domain_data: Dict[str, Any], ssl_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate composite score from domain and SSL data

        Args:
            domain_data: Dict with 'domain_age_years' key
            ssl_data: Dict with SSL certificate information

        Returns:
            Dict with composite_score, domain_score, ssl_score, trust_level
        """
        # Extract domain age
        domain_age_years = domain_data.get("domain_age_years")

        # Calculate individual scores
        domain_score = calculate_domain_age_score(domain_age_years)
        ssl_score = calculate_ssl_score(ssl_data)

        # Calculate composite score with weights
        composite = calculate_weighted_composite_score(
            domain_score, ssl_score, self.domain_weight, self.ssl_weight
        )

        # Determine trust level
        trust_level = self._get_trust_level(composite)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            composite, domain_age_years, ssl_data
        )

        return {
            "composite_score": round(composite, 1),
            "domain_score": round(domain_score, 1),
            "ssl_score": round(ssl_score, 1),
            "trust_level": trust_level,
            "domain_weight": self.domain_weight,
            "ssl_weight": self.ssl_weight,
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
        if not ssl_data.get("is_valid"):
            recommendations.append(
                "SSL certificate is invalid - avoid entering sensitive data"
            )
        elif ssl_data.get("expiring_soon"):
            recommendations.append(
                "SSL certificate expiring soon"
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


def calculate_weighted_composite_score(
    domain_score: float,
    ssl_score: float,
    domain_weight: float = 0.6,
    ssl_weight: float = 0.4,
) -> float:
    """
    Calculate weighted composite score

    Args:
        domain_score: Domain age score (0-100)
        ssl_score: SSL security score (0-100)
        domain_weight: Weight for domain score (default 0.6)
        ssl_weight: Weight for SSL score (default 0.4)

    Returns:
        Composite score (0-100)
    """
    composite = (domain_score * domain_weight) + (ssl_score * ssl_weight)
    return round(composite, 1)


def calculate_composite_score(
    domain_age_years: Optional[float] = None,
    ssl_valid: bool = False,
    ssl_days_remaining: int = 0,
    ssl_issuer: str = "",
) -> Dict[str, Any]:
    """
    Calculate composite score from raw parameters
    This is the function called by app.py

    Args:
        domain_age_years: Age of domain in years
        ssl_valid: Whether SSL certificate is valid
        ssl_days_remaining: Days until SSL expiry
        ssl_issuer: SSL certificate issuer

    Returns:
        Dict with composite_score, trust_level, and details
    """
    try:
        # Calculate domain score
        domain_score = calculate_domain_age_score(domain_age_years)

        # Build SSL data dict
        ssl_data = {
            "valid": ssl_valid,
            "is_valid": ssl_valid,
            "days_until_expiry": ssl_days_remaining,
            "expiring_soon": (ssl_days_remaining < 30
                              if ssl_days_remaining is not None
                              else False),
            "issuer": ssl_issuer
        }

        # Calculate SSL score
        ssl_score = calculate_ssl_score(ssl_data)

        # Calculate weighted composite
        composite = calculate_weighted_composite_score(domain_score, ssl_score)

        # Determine trust level
        if composite >= 80:
            trust_level = "high"
        elif composite >= 60:
            trust_level = "medium"
        else:
            trust_level = "low"

        return {
            "composite_score": composite,
            "domain_score": domain_score,
            "ssl_score": ssl_score,
            "trust_level": trust_level,
            "details": {
                "domain_age_years": domain_age_years,
                "ssl_valid": ssl_valid,
                "ssl_days_remaining": ssl_days_remaining
            }
        }
    except Exception as e:
        logger.error(f"Error calculating composite score: {e}")
        return {
            "composite_score": 0,
            "trust_level": "error",
            "details": str(e)
        }