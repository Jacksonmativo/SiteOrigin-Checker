import ssl
import re
import socket
import OpenSSL.crypto
from datetime import datetime
from urllib.parse import urlparse
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def sanitize_domain(domain: str) -> str:
    """Remove any script tags or suspicious characters from domain input"""
    # Remove <, >, quotes, and parentheses
    domain = re.sub(r'[<>"\'()]', '', domain)
    # Remove any <script> or HTML tags
    domain = re.sub(r'<.*?>', '', domain)
    return domain.strip()


def check_ssl_certificate(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check SSL certificate validity and details

    Args:
        url: The URL to check (e.g., 'https://example.com')
        timeout: Connection timeout in seconds (default: 10)

    Returns:
        dict with certificate information
    """
    result = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'expiry_date': None,
        'days_until_expiry': None,
        'cipher_strength': None,
        'protocol_version': None,
        'error': None
    }

    try:
        # Parse URL to get hostname and port
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc or parsed.path.split(
            '/')[0]
        port = parsed.port or 443
        hostname = sanitize_domain(hostname)

        # Remove www. prefix if present for connection
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        # Clean hostname of any remaining path components
        if '/' in hostname:
            hostname = hostname.split('/')[0]

        logger.info(f"Checking SSL for {hostname}:{port}")

        # Create SSL context
        context = ssl.create_default_context()

        # Connect and get certificate
        with socket.create_connection(
            (hostname, port), timeout=timeout
        ) as sock:
            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as ssock:
                # Get certificate details
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()

                # Parse certificate with OpenSSL for more details
                x509 = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1,
                    cert_bin
                )

                # Extract issuer
                issuer_components = x509.get_issuer().get_components()
                issuer_dict = {
                    k.decode(): v.decode()
                    for k, v in issuer_components
                }
                result['issuer'] = issuer_dict.get(
                    'O', issuer_dict.get('CN', 'Unknown')
                )

                # Extract subject
                subject_components = x509.get_subject().get_components()
                subject_dict = {
                    k.decode(): v.decode()
                    for k, v in subject_components
                }
                result['subject'] = subject_dict.get('CN', hostname)

                # Check expiry
                not_after_str = x509.get_notAfter().decode('ascii')
                expiry_date = datetime.strptime(
                    not_after_str, '%Y%m%d%H%M%SZ'
                )
                result['expiry_date'] = expiry_date.isoformat()

                # Calculate days until expiry
                days_remaining = (expiry_date - datetime.now()).days
                result['days_until_expiry'] = days_remaining

                # Get cipher strength and protocol
                if cipher:
                    result['cipher_strength'] = check_cipher_strength(cipher)

                result['protocol_version'] = protocol

                # Determine if certificate is valid
                is_expired = days_remaining <= 0
                is_self_signed_cert = is_self_signed(x509)

                # Mark as valid if not expired and not self-signed
                result['valid'] = not is_expired and not is_self_signed_cert

                # Set appropriate error messages
                if is_expired:
                    result['error'] = 'Certificate has expired'
                    result['valid'] = False
                elif days_remaining < 30:
                    result['error'] = (
                        'Certificate expiring soon (less than 30 days)'
                    )
                elif is_self_signed_cert:
                    result['error'] = 'Self-signed certificate'
                    result['valid'] = False

                logger.info(
                    f"SSL check successful for {hostname}: "
                    f"valid={result['valid']}, "
                    f"days_remaining={days_remaining}"
                )

    except ssl.SSLCertVerificationError as e:
        logger.error(
            f"SSL certificate verification failed for {url}: {str(e)}"
        )
        result['error'] = f"Certificate verification failed: {str(e)}"
        result['valid'] = False
    except ssl.SSLError as e:
        logger.error(f"SSL error for {url}: {str(e)}")
        result['error'] = f"SSL Error: {str(e)}"
        result['valid'] = False
    except socket.timeout:
        logger.error(f"Timeout checking SSL for {url}")
        result['error'] = "Connection timeout"
        result['valid'] = False
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {url}: {str(e)}")
        result['error'] = f"DNS resolution failed: {str(e)}"
        result['valid'] = False
    except Exception as e:
        logger.error(f"Error checking SSL for {url}: {str(e)}")
        result['error'] = str(e)
        result['valid'] = False

    return result


def is_self_signed(cert: OpenSSL.crypto.X509) -> bool:
    """Check if certificate is self-signed"""
    try:
        issuer = cert.get_issuer()
        subject = cert.get_subject()

        # Compare issuer and subject
        issuer_str = str(issuer.get_components())
        subject_str = str(subject.get_components())

        return issuer_str == subject_str
    except Exception as e:
        logger.warning(
            f"Error checking if certificate is self-signed: {e}"
        )
        return False


def is_trusted_issuer(issuer: str) -> bool:
    """Check if the issuer is from a known trusted CA"""
    if not issuer:
        return False

    trusted_cas = [
        'DigiCert', "Let's Encrypt", 'GeoTrust', 'Comodo', 'Sectigo',
        'GlobalSign', 'GoDaddy', 'Entrust', 'Thawte', 'RapidSSL',
        'Symantec', 'VeriSign', 'Amazon', 'Google Trust Services',
        'Microsoft', 'CloudFlare', 'cPanel', 'Plesk', 'ZeroSSL',
        'IdenTrust', 'DST Root CA', 'ISRG Root', 'WR2', 'WE1',
        'R3', 'R10', 'E1', 'E5'
    ]

    issuer_lower = issuer.lower()
    return any(ca.lower() in issuer_lower for ca in trusted_cas)


def get_certificate_chain(hostname: str, port: int = 443) -> list:
    """Get the full certificate chain"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection(
            (hostname, port), timeout=10
        ) as sock:
            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as ssock:
                # Get peer certificate chain
                der_cert_bin = ssock.getpeercert(True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert_bin)
                return [pem_cert]
    except Exception as e:
        logger.error(f"Error getting certificate chain: {str(e)}")
        return []


def check_cipher_strength(cipher_info: tuple) -> str:
    """Evaluate cipher strength"""
    if not cipher_info or len(cipher_info) < 3:
        return "unknown"

    bits = cipher_info[2]

    if bits >= 256:
        return "strong"
    elif bits >= 128:
        return "medium"
    else:
        return "weak"


def check_protocol_security(protocol: str) -> str:
    """Check if the SSL/TLS protocol version is secure"""
    secure_protocols = ['TLSv1.2', 'TLSv1.3']
    deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']

    if protocol in secure_protocols:
        return "secure"
    elif protocol in deprecated_protocols:
        return "deprecated"
    else:
        return "unknown"
