#!/usr/bin/env python3
"""
DNS Checker Module
Verifies DNS records and security configurations for domains
"""

try:
    import dns.resolver  # type: ignore[reportMissingImports]
    import dns.exception  # type: ignore[reportMissingImports]
    DNS_AVAILABLE = True
except Exception:
    # dnspython not available in this environment; provide fallbacks
    DNS_AVAILABLE = False
    dns = None
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def check_dns_records(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check DNS records and calculate reliability score

    Args:
        domain: Domain name to check (can be URL or plain domain)
        timeout: DNS query timeout in seconds

    Returns:
        Dict containing:
            - a_records: List of A records (IPv4)
            - aaaa_records: List of AAAA records (IPv6)
            - mx_records: List of MX records
            - ns_records: List of NS records
            - txt_records: List of TXT records
            - spf_record: SPF record if found
            - dmarc_record: DMARC record if found
            - dkim_configured: Whether DKIM appears configured
            - dns_score: Score from 0.0 to 1.0
            - dns_reliability: 'high', 'medium', or 'low'
            - recommendations: List of recommendations
            - error: Error message if check failed
    """
    result = {
        'a_records': [],
        'aaaa_records': [],
        'mx_records': [],
        'ns_records': [],
        'txt_records': [],
        'spf_record': None,
        'dmarc_record': None,
        'dkim_configured': False,
        'dns_score': 0.0,
        'dns_reliability': 'unknown',
        'recommendations': [],
        'error': None
    }

    try:
        # Parse domain from URL if needed
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            hostname = parsed.hostname or parsed.netloc
        else:
            hostname = domain

        # Remove www. prefix
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        logger.info(f"Checking DNS records for {hostname}")

        # If dnspython isn't installed, return an informative error.
        if not DNS_AVAILABLE:
            result['error'] = "dnspython not installed"
            return result

        # Configure resolver with timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Check A records (IPv4)
        result['a_records'] = _query_dns_records(
            resolver, hostname, 'A'
        )

        # Check AAAA records (IPv6)
        result['aaaa_records'] = _query_dns_records(
            resolver, hostname, 'AAAA'
        )

        # Check MX records
        mx_data = _query_dns_records(
            resolver, hostname, 'MX', return_objects=True
        )
        if mx_data:
            result['mx_records'] = [
                {
                    'priority': mx.preference,
                    'host': str(mx.exchange).rstrip('.')
                }
                for mx in mx_data
            ]

        # Check NS records
        result['ns_records'] = _query_dns_records(
            resolver, hostname, 'NS'
        )

        # Check TXT records
        txt_records = _query_dns_records(resolver, hostname, 'TXT')
        result['txt_records'] = txt_records

        # Parse TXT records for security configurations
        security_data = _parse_security_records(txt_records, hostname)
        result['spf_record'] = security_data['spf']
        result['dmarc_record'] = security_data['dmarc']
        result['dkim_configured'] = security_data['dkim_configured']

        # Calculate DNS score
        score_data = _calculate_dns_score(result)
        result['dns_score'] = score_data['score']
        result['dns_reliability'] = score_data['reliability']
        result['recommendations'] = score_data['recommendations']

        logger.info(
            f"DNS check complete for {hostname}: "
            f"score={result['dns_score']:.2f}, "
            f"A={len(result['a_records'])}, "
            f"MX={len(result['mx_records'])}, "
            f"NS={len(result['ns_records'])}"
        )

        # If all primary record sets are empty, mark as error to indicate
        # possible NXDOMAIN or misconfiguration. This helps tests detect
        # invalid domains.
        if (
            not result['a_records']
            and not result['aaaa_records']
            and not result['mx_records']
            and not result['ns_records']
        ):
            result['error'] = "No DNS records found"

    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain does not exist: {domain}")
        result['error'] = "Domain does not exist (NXDOMAIN)"
    except dns.resolver.NoNameservers:
        logger.error(f"No nameservers found for {domain}")
        result['error'] = "No nameservers available"
    except dns.resolver.Timeout:
        logger.error(f"DNS query timeout for {domain}")
        result['error'] = "DNS query timeout"
    except dns.exception.DNSException as e:
        logger.error(f"DNS error for {domain}: {str(e)}")
        result['error'] = f"DNS error: {str(e)}"
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {str(e)}")
        result['error'] = str(e)

    return result


def _query_dns_records(
    resolver: Any,
    hostname: str,
    record_type: str,
    return_objects: bool = False
) -> List:
    """
    Query DNS records of a specific type

    Args:
        resolver: DNS resolver instance
        hostname: Domain to query
        record_type: Type of DNS record (A, AAAA, MX, NS, TXT)
        return_objects: Return raw objects instead of strings

    Returns:
        List of records (strings or objects)
    """
    try:
        answers = resolver.resolve(hostname, record_type)
        if return_objects:
            return [answer for answer in answers]
        else:
            if record_type == 'TXT':
                # TXT records need special handling for quotes
                return [
                    ''.join(
                        [
                            s.decode() if isinstance(s, bytes) else str(s)
                            for s in answer.strings
                        ]
                    )
                    for answer in answers
                ]
            else:
                return [str(answer).rstrip('.') for answer in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers
    ):
        return []
    except Exception as e:
        logger.debug(
            f"Error querying {record_type} for {hostname}: {str(e)}"
        )
        return []


def _parse_security_records(
    txt_records: List[str], hostname: str
) -> Dict[str, Any]:
    """
    Parse TXT records for security-related configurations

    Args:
        txt_records: List of TXT records
        hostname: Domain name

    Returns:
        Dict with spf, dmarc, and dkim_configured
    """
    spf_record = None
    dmarc_record = None
    dkim_configured = False

    # Check for SPF in TXT records
    for record in txt_records:
        record_lower = record.lower()
        if record_lower.startswith('v=spf1'):
            spf_record = record
            break

    # Check DMARC (_dmarc subdomain)
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        dmarc_domain = f"_dmarc.{hostname}"
        dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
        for answer in dmarc_answers:
            # Handle TXT record format
            record_parts = []
            for s in answer.strings:
                if isinstance(s, bytes):
                    record_parts.append(s.decode())
                else:
                    record_parts.append(str(s))
            record = ''.join(record_parts)

            if record.lower().startswith('v=dmarc1'):
                dmarc_record = record
                break
    except (dns.exception.DNSException,) as e:
        # DNS issues (no record, NXDOMAIN, no nameservers, etc.)
        logger.debug(f"DMARC lookup failed for {hostname}: {e}")
    except Exception as e:
        # Unexpected errors should be logged
        logger.warning(f"Unexpected DMARC check error for {hostname}: {e}")

    # Check for common DKIM selectors
    common_selectors = [
        'default', 'google', 'k1', 'dkim', 'mail',
        'selector1', 'selector2', 's1', 's2'
    ]
    for selector in common_selectors:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            dkim_domain = f"{selector}._domainkey.{hostname}"
            dkim_answers = resolver.resolve(dkim_domain, 'TXT')
            if dkim_answers:
                dkim_configured = True
                break
        except (dns.exception.DNSException,) as e:
            # Expected DNS lookup issues for selectors
            logger.debug(f"DKIM selector lookup failed for {selector}: {e}")
            continue
        except Exception as e:
            logger.warning(
                f"Unexpected error checking DKIM selector {selector}: {e}"
            )
            continue

    return {
        'spf': spf_record,
        'dmarc': dmarc_record,
        'dkim_configured': dkim_configured
    }


def _calculate_dns_score(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate DNS reliability score

    Args:
        dns_data: Dictionary with DNS records

    Returns:
        Dict with score, reliability, and recommendations
    """
    score = 0.0
    recommendations = []

    # A records (20% of score)
    if len(dns_data['a_records']) > 0:
        score += 0.20
    else:
        recommendations.append("No A records (IPv4) found")

    # AAAA records (10% of score) - optional but good to have
    if len(dns_data['aaaa_records']) > 0:
        score += 0.10
    else:
        recommendations.append(
            "Consider adding AAAA records (IPv6) for future-proofing"
        )

    # MX records (15% of score)
    if len(dns_data['mx_records']) > 0:
        score += 0.15
        if len(dns_data['mx_records']) > 1:
            # Multiple MX records show redundancy
            score += 0.05
    else:
        recommendations.append(
            "No MX records found - email may not be configured"
        )

    # NS records (20% of score)
    ns_count = len(dns_data['ns_records'])
    if ns_count >= 2:
        score += 0.20
    elif ns_count == 1:
        score += 0.10
        recommendations.append(
            "Only one NS record - add backup nameservers for reliability"
        )
    else:
        recommendations.append("No NS records found")

    # SPF record (10% of score)
    if dns_data['spf_record']:
        score += 0.10
    else:
        recommendations.append(
            "No SPF record found - add to prevent email spoofing"
        )

    # DMARC record (15% of score)
    if dns_data['dmarc_record']:
        score += 0.15
    else:
        recommendations.append(
            "No DMARC record found - add for email authentication"
        )

    # DKIM (10% of score)
    if dns_data['dkim_configured']:
        score += 0.10
    else:
        recommendations.append(
            "DKIM not detected - configure for email security"
        )

    # Determine reliability category
    if score >= 0.80:
        reliability = 'high'
        recommendations.insert(
            0, "Excellent DNS configuration with security features"
        )
    elif score >= 0.60:
        reliability = 'medium'
        recommendations.insert(
            0, "Good DNS setup - consider adding missing security records"
        )
    elif score >= 0.40:
        reliability = 'low'
        recommendations.insert(
            0, "Basic DNS setup - missing important records"
        )
    else:
        reliability = 'very_low'
        recommendations.insert(
            0, "Incomplete DNS configuration - multiple records missing"
        )

    return {
        'score': round(score, 2),
        'reliability': reliability,
        'recommendations': recommendations
    }


def verify_dnssec(domain: str) -> Dict[str, Any]:
    """
    Check if DNSSEC is enabled for the domain

    Args:
        domain: Domain name to check

    Returns:
        Dict with dnssec_enabled boolean and details
    """
    result = {
        'dnssec_enabled': False,
        'ds_records': [],
        'error': None
    }

    try:
        # Parse domain from URL if needed
        if domain.startswith('http'):
            domain = urlparse(domain).hostname

        if domain.startswith('www.'):
            domain = domain[4:]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5

        # Check for DS records (DNSSEC delegation signer)
        try:
            ds_answers = resolver.resolve(domain, 'DS')
            result['ds_records'] = [str(ds) for ds in ds_answers]
            result['dnssec_enabled'] = True
        except dns.resolver.NoAnswer:
            result['dnssec_enabled'] = False
        except dns.exception.DNSException as e:
            # DNSSEC not configured or query failed
            logger.debug(f"DNSSEC verification failed: {e}")
            result['dnssec_enabled'] = False
        except Exception as e:
            # Unexpected errors
            logger.warning(f"Unexpected DNSSEC check error: {e}")
            result['dnssec_enabled'] = False

    except Exception as e:
        logger.error(f"Error checking DNSSEC for {domain}: {str(e)}")
        result['error'] = str(e)

    return result
