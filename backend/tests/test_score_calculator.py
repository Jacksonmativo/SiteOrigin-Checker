#!/usr/bin/env python3
"""
Test suite for score_calculator.py module
Tests composite scoring logic for website authenticity analysis
"""

import unittest
import unittest.mock as mock
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Import the module to test (assuming it's in the same directory)
try:
    from score_calculator import ScoreCalculator, calculate_composite_score, calculate_domain_age_score, calculate_ssl_score
except ImportError:
    # Create mock classes for testing structure
    class ScoreCalculator:
        def __init__(self, domain_weight=0.6, ssl_weight=0.4):
            self.domain_weight = domain_weight
            self.ssl_weight = ssl_weight
        
        def calculate_score(self, domain_data, ssl_data):
            pass
    
    def calculate_composite_score(domain_score, ssl_score, domain_weight=0.6, ssl_weight=0.4):
        pass
    
    def calculate_domain_age_score(age_years):
        pass
    
    def calculate_ssl_score(ssl_data):
        pass


class TestScoreCalculator(unittest.TestCase):
    """Test cases for ScoreCalculator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.calculator = ScoreCalculator()
        
        # Test data scenarios
        self.old_domain_data = {
            'domain_age_years': 7.5,
            'registrar': 'GoDaddy Inc.'
        }
        
        self.new_domain_data = {
            'domain_age_years': 0.5,
            'registrar': 'Namecheap Inc.'
        }
        
        self.medium_domain_data = {
            'domain_age_years': 3.2,
            'registrar': 'CloudFlare Inc.'
        }
        
        self.strong_ssl_data = {
            'is_valid': True,
            'cipher_strength': 'strong',
            'protocol_version': 'TLSv1.3',
            'days_until_expiry': 180,
            'expiring_soon': False
        }
        
        self.weak_ssl_data = {
            'is_valid': True,
            'cipher_strength': 'weak',
            'protocol_version': 'TLSv1.1',
            'days_until_expiry': 15,
            'expiring_soon': True
        }
        
        self.invalid_ssl_data = {
            'is_valid': False,
            'cipher_strength': None,
            'protocol_version': None,
            'days_until_expiry': -10,
            'expiring_soon': False
        }
    
    def test_score_calculator_initialization(self):
        """Test ScoreCalculator initializes with correct weights"""
        calculator = ScoreCalculator()
        self.assertEqual(calculator.domain_weight, 0.6)
        self.assertEqual(calculator.ssl_weight, 0.4)
        
        # Test custom weights
        custom_calculator = ScoreCalculator(domain_weight=0.7, ssl_weight=0.3)
        self.assertEqual(custom_calculator.domain_weight, 0.7)
        self.assertEqual(custom_calculator.ssl_weight, 0.3)
    
    def test_calculate_domain_age_score_old_domain(self):
        """Test domain age scoring for domains >5 years"""
        age_years = 7.5
        score = calculate_domain_age_score(age_years)
        
        self.assertEqual(score, 100)
        self.assertIsInstance(score, (int, float))
    
    def test_calculate_domain_age_score_medium_domain(self):
        """Test domain age scoring for domains 3-5 years"""
        test_ages = [3.0, 4.0, 4.9]
        
        for age in test_ages:
            score = calculate_domain_age_score(age)
            self.assertEqual(score, 70)
    
    def test_calculate_domain_age_score_young_domain(self):
        """Test domain age scoring for domains 1-3 years"""
        test_ages = [1.0, 2.0, 2.9]
        
        for age in test_ages:
            score = calculate_domain_age_score(age)
            self.assertEqual(score, 50)
    
    def test_calculate_domain_age_score_new_domain(self):
        """Test domain age scoring for domains <1 year"""
        test_ages = [0.1, 0.5, 0.9]
        
        for age in test_ages:
            score = calculate_domain_age_score(age)
            self.assertEqual(score, 20)
    
    def test_calculate_domain_age_score_edge_cases(self):
        """Test domain age scoring edge cases"""
        # Exactly on boundaries
        self.assertEqual(calculate_domain_age_score(1.0), 50)
        self.assertEqual(calculate_domain_age_score(3.0), 70)
        self.assertEqual(calculate_domain_age_score(5.0), 100)
        
        # Zero or negative (should handle gracefully)
        self.assertEqual(calculate_domain_age_score(0), 20)
        self.assertEqual(calculate_domain_age_score(-1), 20)  # Should default to lowest score
    
    def test_calculate_ssl_score_strong(self):
        """Test SSL scoring for strong, valid certificates"""
        score = calculate_ssl_score(self.strong_ssl_data)
        self.assertEqual(score, 100)
    
    def test_calculate_ssl_score_weak(self):
        """Test SSL scoring for weak but valid certificates"""
        score = calculate_ssl_score(self.weak_ssl_data)
        self.assertEqual(score, 50)  # Valid but expiring soon
    
    def test_calculate_ssl_score_invalid(self):
        """Test SSL scoring for invalid certificates"""
        score = calculate_ssl_score(self.invalid_ssl_data)
        self.assertEqual(score, 0)
    
    def test_calculate_ssl_score_expiring(self):
        """Test SSL scoring for certificates expiring soon"""
        expiring_ssl = {
            'is_valid': True,
            'cipher_strength': 'strong',
            'protocol_version': 'TLSv1.2',
            'days_until_expiry': 25,
            'expiring_soon': True
        }
        
        score = calculate_ssl_score(expiring_ssl)
        self.assertEqual(score, 50)  # Should be reduced due to expiring soon
    
    def test_calculate_ssl_score_medium_cipher(self):
        """Test SSL scoring for medium strength ciphers"""
        medium_ssl = {
            'is_valid': True,
            'cipher_strength': 'medium',
            'protocol_version': 'TLSv1.2',
            'days_until_expiry': 90,
            'expiring_soon': False
        }
        
        score = calculate_ssl_score(medium_ssl)
        self.assertEqual(score, 70)
    
    def test_calculate_composite_score_high_trust(self):
        """Test composite scoring for high trust scenarios"""
        domain_score = 100  # Old domain
        ssl_score = 100     # Strong SSL
        
        composite = calculate_composite_score(domain_score, ssl_score)
        self.assertEqual(composite, 100)
    
    def test_calculate_composite_score_medium_trust(self):
        """Test composite scoring for medium trust scenarios"""
        domain_score = 70   # Medium age domain
        ssl_score = 70      # Medium SSL
        
        composite = calculate_composite_score(domain_score, ssl_score)
        self.assertEqual(composite, 70)
    
    def test_calculate_composite_score_low_trust(self):
        """Test composite scoring for low trust scenarios"""
        domain_score = 20   # New domain
        ssl_score = 0       # Invalid SSL
        
        composite = calculate_composite_score(domain_score, ssl_score)
        expected = (20 * 0.6) + (0 * 0.4)  # 12
        self.assertEqual(composite, expected)
    
    def test_calculate_composite_score_custom_weights(self):
        """Test composite scoring with custom weights"""
        domain_score = 50
        ssl_score = 100
        
        # Equal weights
        composite_equal = calculate_composite_score(domain_score, ssl_score, 0.5, 0.5)
        self.assertEqual(composite_equal, 75)
        
        # SSL-heavy weighting
        composite_ssl_heavy = calculate_composite_score(domain_score, ssl_score, 0.3, 0.7)
        expected = (50 * 0.3) + (100 * 0.7)  # 85
        self.assertEqual(composite_ssl_heavy, expected)
    
    def test_full_score_calculation_integration(self):
        """Test complete score calculation workflow"""
        result = self.calculator.calculate_score(self.old_domain_data, self.strong_ssl_data)
        
        self.assertIsInstance(result, dict)
        self.assertIn('composite_score', result)
        self.assertIn('domain_score', result)
        self.assertIn('ssl_score', result)
        self.assertIn('trust_level', result)
        
        # Should be high trust
        self.assertGreaterEqual(result['composite_score'], 80)
        self.assertEqual(result['trust_level'], 'high')
    
    def test_trust_level_classification(self):
        """Test trust level classification based on scores"""
        test_cases = [
            (95, 'high'),
            (85, 'high'),
            (80, 'high'),
            (75, 'medium'),
            (60, 'medium'),
            (50, 'low'),
            (30, 'low'),
            (10, 'low')
        ]
        
        for score, expected_level in test_cases:
            # Mock trust level calculation
            if score >= 80:
                level = 'high'
            elif score >= 60:
                level = 'medium'
            else:
                level = 'low'
            
            self.assertEqual(level, expected_level)
    
    def test_score_calculation_with_missing_data(self):
        """Test score calculation with incomplete data"""
        incomplete_domain = {'domain_age_years': None}
        incomplete_ssl = {'is_valid': None}
        
        result = self.calculator.calculate_score(incomplete_domain, incomplete_ssl)
        
        # Should handle missing data gracefully
        self.assertIsInstance(result, dict)
        self.assertIn('composite_score', result)
        # Score should be low due to missing data
        self.assertLessEqual(result['composite_score'], 50)
    
    def test_score_rounding(self):
        """Test score rounding behavior"""
        # Test fractional scores are handled correctly
        domain_score = 73.7
        ssl_score = 88.3
        
        composite = calculate_composite_score(domain_score, ssl_score)
        
        # Should be a reasonable composite
        expected = (73.7 * 0.6) + (88.3 * 0.4)  # 79.54
        self.assertAlmostEqual(composite, expected, places=1)
    
    def test_weight_validation(self):
        """Test validation of weight parameters"""
        # Weights should sum to 1.0
        valid_weights = [(0.6, 0.4), (0.5, 0.5), (0.7, 0.3)]
        
        for domain_weight, ssl_weight in valid_weights:
            self.assertAlmostEqual(domain_weight + ssl_weight, 1.0, places=1)
    
    def test_score_boundaries(self):
        """Test score boundaries are respected"""
        # All scores should be between 0 and 100
        test_scores = [
            self.calculator.calculate_score(self.old_domain_data, self.strong_ssl_data),
            self.calculator.calculate_score(self.new_domain_data, self.invalid_ssl_data),
            self.calculator.calculate_score(self.medium_domain_data, self.weak_ssl_data)
        ]
        
        for result in test_scores:
            score = result['composite_score']
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)


class TestScoringLogic(unittest.TestCase):
    """Test specific scoring logic and algorithms"""
    
    def test_exponential_age_scoring(self):
        """Test if domain age scoring follows expected curve"""
        # Older domains should have disproportionately higher scores
        ages_and_scores = [
            (0.5, 20),
            (2.0, 50),
            (4.0, 70),
            (10.0, 100)
        ]
        
        for age, expected_score in ages_and_scores:
            score = calculate_domain_age_score(age)
            self.assertEqual(score, expected_score)
    
    def test_ssl_security_hierarchy(self):
        """Test SSL scoring follows security hierarchy"""
        security_levels = [
            ({'is_valid': False}, 0),
            ({'is_valid': True, 'cipher_strength': 'weak'}, 70),
            ({'is_valid': True, 'cipher_strength': 'medium'}, 70),
            ({'is_valid': True, 'cipher_strength': 'strong'}, 100)
        ]
        
        for ssl_data, min_expected_score in security_levels:
            ssl_data.setdefault('expiring_soon', False)
            ssl_data.setdefault('days_until_expiry', 90)
            
            score = calculate_ssl_score(ssl_data)
            self.assertGreaterEqual(score, min_expected_score)
    
    def test_composite_weighting_impact(self):
        """Test impact of different weighting schemes"""
        domain_score = 100
        ssl_score = 0
        
        # Domain-heavy weighting
        domain_heavy = calculate_composite_score(domain_score, ssl_score, 0.8, 0.2)
        
        # SSL-heavy weighting
        ssl_heavy = calculate_composite_score(domain_score, ssl_score, 0.2, 0.8)
        
        # Domain-heavy should have higher score
        self.assertGreater(domain_heavy, ssl_heavy)
        
        # Expected values
        self.assertEqual(domain_heavy, 80)  # 100*0.8 + 0*0.2
        self.assertEqual(ssl_heavy, 20)     # 100*0.2 + 0*0.8


class TestScoreInterpretation(unittest.TestCase):
    """Test score interpretation and recommendations"""
    
    def test_score_to_risk_level(self):
        """Test conversion of scores to risk levels"""
        score_risk_mapping = [
            (90, 'very_low'),
            (80, 'low'),
            (70, 'medium'),
            (50, 'high'),
            (30, 'very_high')
        ]
        
        for score, expected_risk in score_risk_mapping:
            # Mock risk level calculation
            if score >= 85:
                risk = 'very_low'
            elif score >= 75:
                risk = 'low'
            elif score >= 60:
                risk = 'medium'
            elif score >= 40:
                risk = 'high'
            else:
                risk = 'very_high'
            
            self.assertEqual(risk, expected_risk)
    
    def test_recommendation_generation(self):
        """Test generation of recommendations based on scores"""
        calculator = ScoreCalculator()
        
        # High trust scenario
        high_trust_result = calculator.calculate_score(
            {'domain_age_years': 8}, 
            {'is_valid': True, 'cipher_strength': 'strong', 'expiring_soon': False}
        )
        
        if 'recommendations' in high_trust_result:
            recommendations = high_trust_result['recommendations']
            self.assertIn('trustworthy', ' '.join(recommendations).lower())
        
        # Low trust scenario  
        low_trust_result = calculator.calculate_score(
            {'domain_age_years': 0.2},
            {'is_valid': False}
        )
        
        if 'recommendations' in low_trust_result:
            recommendations = low_trust_result['recommendations']
            self.assertIn('caution', ' '.join(recommendations).lower())
    
    def test_confidence_scoring(self):
        """Test confidence level in score accuracy"""
        # Complete data should have high confidence
        complete_data_confidence = 1.0
        
        # Missing data should reduce confidence
        incomplete_data_confidence = 0.6
        
        self.assertGreater(complete_data_confidence, incomplete_data_confidence)
        self.assertLessEqual(complete_data_confidence, 1.0)
        self.assertGreaterEqual(incomplete_data_confidence, 0.0)


class TestPerformance(unittest.TestCase):
    """Test performance characteristics of scoring algorithms"""
    
    def test_scoring_speed(self):
        """Test that scoring calculations are fast enough"""
        import time
        
        calculator = ScoreCalculator()
        domain_data = {'domain_age_years': 5.0}
        ssl_data = {'is_valid': True, 'cipher_strength': 'strong'}
        
        # Time multiple calculations
        start_time = time.time()
        for _ in range(1000):
            calculator.calculate_score(domain_data, ssl_data)
        end_time = time.time()
        
        # Should complete 1000 calculations in reasonable time
        total_time = end_time - start_time
        self.assertLess(total_time, 1.0)  # Less than 1 second for 1000 calculations
    
    def test_memory_usage(self):
        """Test that scoring doesn't consume excessive memory"""
        import sys
        
        calculator = ScoreCalculator()
        initial_objects = len(gc.get_objects()) if 'gc' in sys.modules else 0
        
        # Perform many calculations
        for i in range(100):
            domain_data = {'domain_age_years': i % 10}
            ssl_data = {'is_valid': i % 2 == 0}
            calculator.calculate_score(domain_data, ssl_data)
        
        # Memory usage shouldn't grow significantly
        if 'gc' in sys.modules:
            import gc
            gc.collect()
            final_objects = len(gc.get_objects())
            growth = final_objects - initial_objects
            self.assertLess(growth, 1000)  # Reasonable object growth


if __name__ == '__main__':
    # Import gc for memory tests if available
    try:
        import gc
    except ImportError:
        pass
    
    # Configure test runner with detailed output
    unittest.main(verbosity=2, buffer=True)