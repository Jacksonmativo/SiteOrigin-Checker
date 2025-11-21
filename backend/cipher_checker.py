#!/usr/bin/env python3
"""
Cipher Checker Module
Analyzes TLS cipher suites and protocol versions for a given domain
"""

import ssl
import socket
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Cipher suite classifications
STRONG_CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
]

WEAK_CIPHERS = [
    'RC4',
    '3DES',
    'DES',
    'NULL',
    'EXPORT',
    'anon',
    'MD5',
]

WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
STRONG_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']


def check_ciphers(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check supported cipher suites and TLS versions for a domain

    Args:
        domain: Domain name or URL to check
        timeout: Connection timeout in seconds

    Returns:
        Dict containing:
            - supported_ciphers: List of cipher suites
            - protocol_version: TLS version used
            - cipher_score: Score from 0.0 to 1.0
            - cipher_strength: 'strong', 'medium', or 'weak'
            - weak_ciphers_found: List of weak ciphers detected
            - recommendations: List of security recommendations
            - error: Error message if check failed
    """
    result = {
        'supported_ciphers': [],
        'protocol_version': None,
        'cipher_score': 0.0,
        'cipher_strength': 'unknown',
        'weak_ciphers_found': [],
        'recommendations': [],
        'error': None
    }

    try:
        # Parse domain from URL if needed
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            hostname = parsed.hostname or parsed.netloc
            port = parsed.port or 443
        else:
            hostname = domain
            port = 443

        # Remove www. prefix
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        logger.info(f"Checking ciphers for {hostname}:{port}")

        # Try to connect with different TLS versions
        protocols_to_test = [
            ('TLSv1.3', ssl.PROTOCOL_TLS_CLIENT),
            ('TLSv1.2', ssl.PROTOCOL_TLS_CLIENT),
        ]

        cipher_info = None
        protocol_used = None

        for protocol_name, protocol_const in protocols_to_test:
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (hostname, port), timeout=timeout
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=hostname
                    ) as ssock:
                        cipher_info = ssock.cipher()
                        protocol_used = ssock.version()
                        result['protocol_version'] = protocol_used

                        # Get shared ciphers if available
                        try:
                            shared_ciphers = ssock.shared_ciphers()
                            # If shared_ciphers returns a non-empty list,
                            # use it.
                            if shared_ciphers:
                                result['supported_ciphers'] = [
                                    c[0] for c in shared_ciphers
                                ]
                            else:
                                # shared_ciphers available but empty; fall back
                                # to the negotiated cipher if present.
                                if cipher_info:
                                    result['supported_ciphers'] = [
                                        cipher_info[0]
                                    ]
                        except AttributeError:
                            # shared_ciphers not available, use cipher()
                            if cipher_info:
                                result['supported_ciphers'] = [cipher_info[0]]

                        break  # Successfully connected

            except (ssl.SSLError, OSError) as e:
                logger.debug(
                    f"Failed to connect with {protocol_name}: {str(e)}"
                )
                continue

        if not cipher_info or not protocol_used:
            result['error'] = "Unable to establish TLS connection"
            return result

        # If we couldn't enumerate cipher suites, fall back to the
        # negotiated cipher from the TLS session (if available) so we
        # still can produce a meaningful score.
        if not result['supported_ciphers'] and cipher_info:
            try:
                result['supported_ciphers'] = [cipher_info[0]]
            except (IndexError, TypeError) as e:
                # Expected errors when cipher_info has unexpected structure
                logger.debug(
                    f"Cipher info parsing failed (empty or wrong format): {e}"
                )
                result['supported_ciphers'] = []

        # Calculate cipher score
        score_data = _calculate_cipher_score(
            result['supported_ciphers'],
            protocol_used
        )

        result['cipher_score'] = score_data['score']
        result['cipher_strength'] = score_data['strength']
        result['weak_ciphers_found'] = score_data['weak_ciphers']
        result['recommendations'] = _generate_cipher_recommendations(
            protocol_used,
            score_data['weak_ciphers'],
            result['supported_ciphers']
        )

        if not result['supported_ciphers']:
            # Indicate error when no ciphers enumerated and we also don't
            # have a negotiated cipher to fall back to.
            result['error'] = "No cipher suites reported"

        logger.info(
            f"Cipher check complete for {hostname}: "
            f"score={result['cipher_score']:.2f}, "
            f"protocol={protocol_used}"
        )

    except socket.timeout:
        logger.error(f"Timeout checking ciphers for {domain}")
        result['error'] = "Connection timeout"
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {domain}: {str(e)}")
        result['error'] = f"DNS resolution failed: {str(e)}"
    except Exception as e:
        logger.error(f"Error checking ciphers for {domain}: {str(e)}")
        result['error'] = str(e)

    return result


def _calculate_cipher_score(
    ciphers: List[str], protocol: str
) -> Dict[str, Any]:
    """
    Calculate cipher strength score based on supported ciphers and protocol

    Args:
        ciphers: List of cipher suite names
        protocol: TLS protocol version

    Returns:
        Dict with score (0.0-1.0), strength, and weak_ciphers list
    """
    if not ciphers:
        return {
            'score': 0.0,
            'strength': 'unknown',
            'weak_ciphers': []
        }

    score = 0.0
    weak_ciphers = []

    # Protocol version scoring (40% of total score)
    if protocol in STRONG_PROTOCOLS:
        score += 0.4
    elif protocol in WEAK_PROTOCOLS:
        score += 0.0
        weak_ciphers.append(f"Weak protocol: {protocol}")
    else:
        score += 0.2  # Unknown/medium protocol

    # Cipher suite scoring (60% of total score)
    cipher_score = 0.0
    strong_count = 0
    weak_count = 0

    for cipher in ciphers:
        cipher_upper = cipher.upper()

        # Check for weak cipher indicators
        is_weak = any(
            weak_indicator in cipher_upper
            for weak_indicator in WEAK_CIPHERS
        )

        if is_weak:
            weak_count += 1
            weak_ciphers.append(cipher)
        else:
            # Check if it's a known strong cipher
            is_strong = any(
                strong_cipher in cipher_upper
                for strong_cipher in STRONG_CIPHERS
            )
            if is_strong:
                strong_count += 1

    # Calculate cipher score based on ratio
    total_ciphers = len(ciphers)
    if total_ciphers > 0:
        if weak_count > 0:
            # Penalize for weak ciphers
            cipher_score = max(
                0.0, 0.6 * (1.0 - (weak_count / total_ciphers))
            )
        else:
            # Reward for strong ciphers
            if strong_count > 0:
                cipher_score = 0.6
            else:
                # Medium ciphers (not weak, not explicitly strong)
                cipher_score = 0.4

    score += cipher_score

    # Determine strength category
    if score >= 0.8:
        strength = 'strong'
    elif score >= 0.5:
        strength = 'medium'
    else:
        strength = 'weak'

    return {
        'score': round(score, 2),
        'strength': strength,
        'weak_ciphers': weak_ciphers
    }


def _generate_cipher_recommendations(
    protocol: str, weak_ciphers: List[str], all_ciphers: List[str]
) -> List[str]:
    """Generate security recommendations based on cipher analysis"""
    recommendations = []

    if protocol in WEAK_PROTOCOLS:
        recommendations.append(
            f"Upgrade from {protocol} to TLS 1.2 or 1.3 for better security"
        )

    if weak_ciphers:
        recommendations.append(
            f"Disable {len(weak_ciphers)} weak cipher suite(s) detected"
        )

    if protocol == 'TLSv1.3':
        recommendations.append(
            "Excellent: Using TLS 1.3 with modern ciphers"
        )
    elif protocol == 'TLSv1.2' and not weak_ciphers:
        recommendations.append(
            "Good: Using TLS 1.2 with secure ciphers"
        )

    if not all_ciphers:
        recommendations.append(
            "Unable to enumerate cipher suites"
        )

    return recommendations


def get_detailed_cipher_info(domain: str) -> Dict[str, Any]:
    """
    Get detailed cipher information including all tested protocols

    Args:
        domain: Domain name to check

    Returns:
        Dict with detailed cipher analysis for each protocol version
    """
    protocols = {
        'TLSv1.3': ssl.PROTOCOL_TLS_CLIENT,
        'TLSv1.2': ssl.PROTOCOL_TLS_CLIENT,
    }

    results = {}

    for protocol_name, protocol_const in protocols.items():
        try:
            context = ssl.SSLContext(protocol_const)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            hostname = domain
            if domain.startswith('http'):
                hostname = urlparse(domain).hostname

            if hostname.startswith('www.'):
                hostname = hostname[4:]

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(
                    sock, server_hostname=hostname
                ) as ssock:
                    cipher = ssock.cipher()
                    results[protocol_name] = {
                        'supported': True,
                        'cipher': cipher[0] if cipher else None,
                        'protocol_version': ssock.version(),
                        'bits': cipher[2] if cipher else None
                    }
        except Exception as e:
            results[protocol_name] = {
                'supported': False,
                'error': str(e)
            }

    return results
