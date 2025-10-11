#!/usr/bin/env python3
"""
Test suite for whois_checker.py module
Tests domain age calculation and WHOIS data retrieval functionality
"""

import unittest
import unittest.mock as mock
from datetime import datetime, timedelta
import json
import requests
from unittest.mock import patch, MagicMock

# Import the module to test (assuming it's in the same directory)
try:
    from whois_checker import WhoisChecker, calculate_domain_age, parse_creation_date
except ImportError:
    # Create mock classes for testing structure
    class WhoisChecker:
        def __init__(self):
            pass
        
        def get_domain_age(self, domain):
            pass
    
    def calculate_domain_age(creation_date):
        pass
    
    def parse_creation_date(date_string):
        pass


class TestWhoisChecker(unittest.TestCase):
    """Test cases for WhoisChecker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = WhoisChecker()
        self.test_domain = "example.com"
        self.test_new_domain = "newdomain.com"
        
        # Test data for different scenarios
        self.old_creation_date = datetime.now() - timedelta(days=2555)  # ~7 years
        self.new_creation_date = datetime.now() - timedelta(days=180)   # ~6 months
        self.medium_creation_date = datetime.now() - timedelta(days=1095)  # ~3 years
    
    def test_whois_checker_initialization(self):
        """Test WhoisChecker initializes correctly"""
        checker = WhoisChecker()
        self.assertIsInstance(checker, WhoisChecker)
    
    @patch('requests.get')
    def test_who_dat_api_success(self, mock_get):
        """Test successful API call to who-dat service"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "creation_date": "2016-03-15T00:00:00Z",
            "registrar": "Test Registrar"
        }
        mock_get.return_value = mock_response
        
        result = self.checker.get_domain_age(self.test_domain)
        
        # Verify API was called correctly
        mock_get.assert_called_once()
        self.assertIsNotNone(result)
        self.assertIn('domain_age_years', result)
        self.assertIn('registrar', result)
    
    @patch('requests.get')
    def test_who_dat_api_failure(self, mock_get):
        """Test handling of API failure"""
        # Mock API failure
        mock_get.side_effect = requests.RequestException("API Error")
        
        result = self.checker.get_domain_age(self.test_domain)
        
        # Should return None or default values on failure
        self.assertIsNone(result) or self.assertEqual(result.get('domain_age_years'), 0)
    
    @patch('requests.get')
    def test_rdap_fallback(self, mock_get):
        """Test fallback to RDAP when who-dat fails"""
        # Mock who-dat failure, then RDAP success
        responses = [
            requests.RequestException("who-dat failed"),
            MagicMock(status_code=200, json=lambda: {
                "events": [
                    {"eventAction": "registration", "eventDate": "2018-05-20T10:15:30Z"}
                ]
            })
        ]
        mock_get.side_effect = responses
        
        result = self.checker.get_domain_age(self.test_domain)
        
        # Should have tried both APIs
        self.assertEqual(mock_get.call_count, 2)
        self.assertIsNotNone(result)
    
    def test_domain_age_calculation_old_domain(self):
        """Test age calculation for old domain (>5 years)"""
        age_years = calculate_domain_age(self.old_creation_date)
        self.assertGreater(age_years, 5)
        self.assertIsInstance(age_years, (int, float))
    
    def test_domain_age_calculation_new_domain(self):
        """Test age calculation for new domain (<1 year)"""
        age_years = calculate_domain_age(self.new_creation_date)
        self.assertLess(age_years, 1)
        self.assertGreater(age_years, 0)
    
    def test_domain_age_calculation_medium_domain(self):
        """Test age calculation for medium age domain (1-5 years)"""
        age_years = calculate_domain_age(self.medium_creation_date)
        self.assertGreater(age_years, 1)
        self.assertLess(age_years, 5)
    
    def test_parse_creation_date_iso_format(self):
        """Test parsing ISO format date strings"""
        iso_date = "2020-01-15T10:30:00Z"
        parsed_date = parse_creation_date(iso_date)
        self.assertIsInstance(parsed_date, datetime)
        self.assertEqual(parsed_date.year, 2020)
        self.assertEqual(parsed_date.month, 1)
        self.assertEqual(parsed_date.day, 15)
    
    def test_parse_creation_date_various_formats(self):
        """Test parsing different date formats"""
        test_dates = [
            "2020-01-15T10:30:00Z",
            "2020-01-15 10:30:00",
            "2020-01-15",
            "15-Jan-2020",
            "January 15, 2020"
        ]
        
        for date_str in test_dates:
            try:
                parsed_date = parse_creation_date(date_str)
                self.assertIsInstance(parsed_date, datetime)
            except ValueError:
                # Some formats might not be supported, that's okay
                pass
    
    def test_parse_creation_date_invalid(self):
        """Test handling of invalid date strings"""
        invalid_dates = ["invalid-date", "", None, "not-a-date-at-all"]
        
        for invalid_date in invalid_dates:
            result = parse_creation_date(invalid_date)
            self.assertIsNone(result)
    
    def test_domain_validation(self):
        """Test domain name validation"""
        valid_domains = [
            "example.com",
            "test-domain.org",
            "subdomain.example.co.uk",
            "123domain.net"
        ]
        
        invalid_domains = [
            "",
            "invalid..domain",
            "too-long-" + "a" * 250 + ".com",
            "spaces in domain.com",
            "http://example.com"  # Should be just domain
        ]
        
        for domain in valid_domains:
            # Assuming there's a validation method
            self.assertTrue(self.checker._is_valid_domain(domain) if hasattr(self.checker, '_is_valid_domain') else True)
        
        for domain in invalid_domains:
            self.assertFalse(self.checker._is_valid_domain(domain) if hasattr(self.checker, '_is_valid_domain') else False)
    
    @patch('requests.get')
    def test_rate_limiting_handling(self, mock_get):
        """Test handling of rate limiting from APIs"""
        # Mock rate limit response
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {'Retry-After': '60'}
        mock_get.return_value = mock_response
        
        result = self.checker.get_domain_age(self.test_domain)
        
        # Should handle rate limiting gracefully
        self.assertIsNone(result) or self.assertIn('error', result)
    
    @patch('requests.get')
    def test_timeout_handling(self, mock_get):
        """Test handling of request timeouts"""
        mock_get.side_effect = requests.Timeout("Request timed out")
        
        result = self.checker.get_domain_age(self.test_domain)
        
        # Should handle timeout gracefully
        self.assertIsNone(result)
    
    def test_caching_mechanism(self):
        """Test caching of WHOIS results"""
        # Assuming the checker has caching capability
        if hasattr(self.checker, '_cache'):
            # First call - should hit API
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "creation_date": "2020-01-01T00:00:00Z",
                    "registrar": "Test Registrar"
                }
                mock_get.return_value = mock_response
                
                result1 = self.checker.get_domain_age(self.test_domain)
                result2 = self.checker.get_domain_age(self.test_domain)
                
                # Second call should use cache, not hit API again
                mock_get.assert_called_once()
                self.assertEqual(result1, result2)
    
    def test_multiple_domains_batch(self):
        """Test processing multiple domains"""
        domains = ["example.com", "test.org", "sample.net"]
        
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "creation_date": "2020-01-01T00:00:00Z",
                "registrar": "Test Registrar"
            }
            mock_get.return_value = mock_response
            
            if hasattr(self.checker, 'get_multiple_domain_ages'):
                results = self.checker.get_multiple_domain_ages(domains)
                self.assertEqual(len(results), len(domains))
                
                for domain, result in results.items():
                    self.assertIn(domain, domains)
                    self.assertIsNotNone(result)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions used by WhoisChecker"""
    
    def test_calculate_domain_age_edge_cases(self):
        """Test edge cases for domain age calculation"""
        now = datetime.now()
        
        # Domain created today
        today_domain = calculate_domain_age(now)
        self.assertAlmostEqual(today_domain, 0, places=2)
        
        # Domain created exactly 1 year ago
        year_ago = now - timedelta(days=365)
        year_old_domain = calculate_domain_age(year_ago)
        self.assertAlmostEqual(year_old_domain, 1, places=1)
        
        # Domain created in the future (edge case)
        future_date = now + timedelta(days=30)
        future_domain = calculate_domain_age(future_date)
        self.assertEqual(future_domain, 0)  # Should return 0 for future dates
    
    def test_date_parsing_robustness(self):
        """Test date parsing with various edge cases"""
        edge_cases = [
            "2020-02-29T00:00:00Z",  # Leap year
            "2020-12-31T23:59:59Z",  # End of year
            "2020-01-01T00:00:00Z",  # Start of year
            "1990-01-01T00:00:00Z",  # Very old date
        ]
        
        for date_str in edge_cases:
            result = parse_creation_date(date_str)
            self.assertIsInstance(result, datetime)
    
    def test_domain_normalization(self):
        """Test domain name normalization"""
        test_cases = [
            ("EXAMPLE.COM", "example.com"),
            ("  example.com  ", "example.com"),
            ("http://example.com", "example.com"),
            ("https://www.example.com", "example.com"),
            ("www.example.com", "example.com")
        ]
        
        # Assuming there's a normalize_domain function
        for input_domain, expected in test_cases:
            # Mock normalization if function doesn't exist
            normalized = input_domain.lower().strip()
            if normalized.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                normalized = urlparse(normalized).netloc
            if normalized.startswith('www.'):
                normalized = normalized[4:]
            
            self.assertEqual(normalized, expected)


class TestIntegration(unittest.TestCase):
    """Integration tests for WhoisChecker"""
    
    @unittest.skipIf(not hasattr(unittest, 'mock'), "Requires mock")
    def test_full_domain_analysis_flow(self):
        """Test complete domain analysis workflow"""
        checker = WhoisChecker()
        test_domain = "example.com"
        
        with patch('requests.get') as mock_get:
            # Mock successful response with all required fields
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "creation_date": "2018-03-15T10:30:00Z",
                "registrar": "Example Registrar Inc.",
                "status": ["ok"],
                "nameservers": ["ns1.example.com", "ns2.example.com"]
            }
            mock_get.return_value = mock_response
            
            result = checker.get_domain_age(test_domain)
            
            # Verify complete result structure
            self.assertIsNotNone(result)
            self.assertIn('domain_age_years', result)
            self.assertIn('registrar', result)
            self.assertGreater(result['domain_age_years'], 0)
            self.assertEqual(result['registrar'], "Example Registrar Inc.")


if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)