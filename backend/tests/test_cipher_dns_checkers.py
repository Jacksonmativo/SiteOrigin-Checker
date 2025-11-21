#!/usr/bin/env python3
"""
Unit tests for cipher_checker and dns_checker modules

NOTE: Bandit B101 warnings about assert statements
------------------------------------------------------
This file uses assert statements extensively, which triggers Bandit's B101 warning.
This is a FALSE POSITIVE for test files because:

1. pytest REQUIRES assert statements for test assertions
2. Tests are never run in optimized mode (python -O)
3. Using assert in tests is industry standard and recommended by pytest docs

Solution: Configure Bandit to exclude test files (see .bandit.yaml)
If you must suppress warnings, they are marked with # nosec B101 below.
"""

import pytest
from cipher_checker import (
    check_ciphers,
    _calculate_cipher_score,
    _generate_cipher_recommendations
)
from dns_checker import (
    check_dns_records,
    _calculate_dns_score,
    _parse_security_records,
    verify_dnssec
)


class TestCipherChecker:
    """Tests for cipher_checker module"""

    def test_check_ciphers_google(self):
        """Test cipher check on Google (known good site)"""
        result = check_ciphers("google.com", timeout=10)

        assert result is not None  # nosec B101
        assert isinstance(result, dict)  # nosec B101
        assert "cipher_score" in result  # nosec B101
        assert "protocol_version" in result  # nosec B101
        assert "cipher_strength" in result  # nosec B101

        # Google should have good security
        if result.get("error") is None:
            assert result["cipher_score"] >= 0.5  # nosec B101
            assert result["protocol_version"] in [  # nosec B101
                "TLSv1.2", "TLSv1.3", None
            ]

    def test_check_ciphers_with_url(self):
        """Test cipher check with full URL"""
        result = check_ciphers("https://www.github.com", timeout=10)

        assert result is not None  # nosec B101
        assert isinstance(result, dict)  # nosec B101
        assert "cipher_score" in result  # nosec B101

    def test_check_ciphers_invalid_domain(self):
        """Test cipher check on invalid domain"""
        result = check_ciphers("thisdoesnotexist12345.com", timeout=5)

        assert result is not None  # nosec B101
        assert result.get("error") is not None  # nosec B101
        assert result["cipher_score"] == 0.0  # nosec B101

    def test_calculate_cipher_score_strong(self):
        """Test cipher score calculation with strong ciphers"""
        ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_AES_256_GCM_SHA384"
        ]
        protocol = "TLSv1.3"

        result = _calculate_cipher_score(ciphers, protocol)

        assert result["score"] >= 0.8  # nosec B101
        assert result["strength"] in ["strong", "medium"]  # nosec B101
        assert len(result["weak_ciphers"]) == 0  # nosec B101

    def test_calculate_cipher_score_weak(self):
        """Test cipher score calculation with weak ciphers"""
        ciphers = ["RC4-SHA", "DES-CBC3-SHA"]
        protocol = "TLSv1.0"

        result = _calculate_cipher_score(ciphers, protocol)

        assert result["score"] < 0.5  # nosec B101
        assert result["strength"] == "weak"  # nosec B101
        assert len(result["weak_ciphers"]) > 0  # nosec B101

    def test_generate_cipher_recommendations(self):
        """Test cipher recommendations generation"""
        weak_ciphers = ["RC4-SHA"]
        all_ciphers = ["RC4-SHA", "AES128-SHA"]
        protocol = "TLSv1.0"

        recommendations = _generate_cipher_recommendations(
            protocol, weak_ciphers, all_ciphers
        )

        assert isinstance(recommendations, list)  # nosec B101
        assert len(recommendations) > 0  # nosec B101
        assert any("Upgrade" in rec or "Disable" in rec  # nosec B101
                   for rec in recommendations)


class TestDNSChecker:
    """Tests for dns_checker module"""

    def test_check_dns_records_google(self):
        """Test DNS check on Google (known good configuration)"""
        result = check_dns_records("google.com", timeout=10)

        assert result is not None  # nosec B101
        assert isinstance(result, dict)  # nosec B101
        assert "dns_score" in result  # nosec B101
        assert "dns_reliability" in result  # nosec B101

        # Google should have comprehensive DNS setup
        if result.get("error") is None:
            assert len(result.get("a_records", [])) > 0  # nosec B101
            assert len(result.get("mx_records", [])) > 0  # nosec B101
            assert len(result.get("ns_records", [])) >= 2  # nosec B101
            assert result["dns_score"] >= 0.6  # nosec B101

    def test_check_dns_records_with_url(self):
        """Test DNS check with full URL"""
        result = check_dns_records("https://www.github.com", timeout=10)

        assert result is not None  # nosec B101
        assert isinstance(result, dict)  # nosec B101
        assert "dns_score" in result  # nosec B101

    def test_check_dns_records_invalid_domain(self):
        """Test DNS check on invalid domain"""
        result = check_dns_records(
            "thisdoesnotexist12345xyz.com", timeout=5
        )

        assert result is not None  # nosec B101
        assert result.get("error") is not None  # nosec B101
        assert result["dns_score"] == 0.0  # nosec B101

    def test_check_dns_records_spf(self):
        """Test SPF record detection"""
        # Gmail is known to have SPF records
        result = check_dns_records("gmail.com", timeout=10)

        if result.get("error") is None:
            # Gmail should have SPF configured
            assert result.get("spf_record") is not None or \  # nosec B101
                   len(result.get("txt_records", [])) > 0

    def test_calculate_dns_score_complete(self):
        """Test DNS score calculation with complete records"""
        dns_data = {
            "a_records": ["1.2.3.4"],
            "aaaa_records": ["2001:db8::1"],
            "mx_records": [
                {"priority": 10, "host": "mail.example.com"}
            ],
            "ns_records": ["ns1.example.com", "ns2.example.com"],
            "spf_record": "v=spf1 include:_spf.example.com ~all",
            "dmarc_record": "v=DMARC1; p=reject",
            "dkim_configured": True
        }

        result = _calculate_dns_score(dns_data)

        assert result["score"] >= 0.9  # nosec B101
        assert result["reliability"] == "high"  # nosec B101
        assert isinstance(result["recommendations"], list)  # nosec B101

    def test_calculate_dns_score_minimal(self):
        """Test DNS score calculation with minimal records"""
        dns_data = {
            "a_records": ["1.2.3.4"],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": ["ns1.example.com"],
            "spf_record": None,
            "dmarc_record": None,
            "dkim_configured": False
        }

        result = _calculate_dns_score(dns_data)

        assert result["score"] < 0.5  # nosec B101
        assert result["reliability"] in ["low", "very_low"]  # nosec B101
        assert len(result["recommendations"]) > 0  # nosec B101

    def test_parse_security_records_with_spf(self):
        """Test parsing TXT records for SPF"""
        txt_records = [
            "v=spf1 include:_spf.google.com ~all",
            "google-site-verification=xyz123"
        ]

        result = _parse_security_records(txt_records, "example.com")

        assert result["spf"] is not None  # nosec B101
        assert result["spf"].startswith("v=spf1")  # nosec B101

    def test_verify_dnssec_cloudflare(self):
        """Test DNSSEC verification on Cloudflare DNS"""
        result = verify_dnssec("cloudflare.com")

        assert result is not None  # nosec B101
        assert isinstance(result, dict)  # nosec B101
        assert "dnssec_enabled" in result  # nosec B101
        # Cloudflare typically has DNSSEC enabled
        if result.get("error") is None:
            assert isinstance(result["dnssec_enabled"], bool)  # nosec B101


class TestIntegration:
    """Integration tests for both modules"""

    def test_combined_check_major_site(self):
        """Test both cipher and DNS checks on a major website"""
        domain = "github.com"

        cipher_result = check_ciphers(domain, timeout=10)
        dns_result = check_dns_records(domain, timeout=10)

        # Both checks should complete
        assert cipher_result is not None  # nosec B101
        assert dns_result is not None  # nosec B101

        # At least one should succeed (unless network issues)
        if cipher_result.get("error") is None:
            assert cipher_result["cipher_score"] > 0  # nosec B101

        if dns_result.get("error") is None:
            assert dns_result["dns_score"] > 0  # nosec B101

    def test_error_handling_timeout(self):
        """Test error handling with very short timeout"""
        cipher_result = check_ciphers("google.com", timeout=0.001)
        dns_result = check_dns_records("google.com", timeout=0.001)

        # Should handle timeouts gracefully
        assert cipher_result is not None  # nosec B101
        assert dns_result is not None  # nosec B101
        # Either succeed or have error field populated
        assert (cipher_result.get("error") is not None or  # nosec B101
                cipher_result.get("cipher_score") is not None)
        assert (dns_result.get("error") is not None or  # nosec B101
                dns_result.get("dns_score") is not None)


# Test fixtures and helpers

@pytest.fixture
def sample_cipher_result():
    """Sample cipher check result"""
    return {
        "supported_ciphers": [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_AES_256_GCM_SHA384"
        ],
        "protocol_version": "TLSv1.3",
        "cipher_score": 0.95,
        "cipher_strength": "strong",
        "weak_ciphers_found": [],
        "recommendations": ["Excellent: Using TLS 1.3 with modern ciphers"],
        "error": None
    }


@pytest.fixture
def sample_dns_result():
    """Sample DNS check result"""
    return {
        "a_records": ["1.2.3.4", "5.6.7.8"],
        "aaaa_records": ["2001:db8::1"],
        "mx_records": [
            {"priority": 10, "host": "mail1.example.com"},
            {"priority": 20, "host": "mail2.example.com"}
        ],
        "ns_records": ["ns1.example.com", "ns2.example.com"],
        "txt_records": ["v=spf1 include:_spf.example.com ~all"],
        "spf_record": "v=spf1 include:_spf.example.com ~all",
        "dmarc_record": "v=DMARC1; p=reject",
        "dkim_configured": True,
        "dns_score": 0.95,
        "dns_reliability": "high",
        "recommendations": [
            "Excellent DNS configuration with security features"
        ],
        "error": None
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])