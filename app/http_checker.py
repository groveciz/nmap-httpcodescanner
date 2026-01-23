"""
HTTP/HTTPS Status Checker Module
"""
import requests
import re
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.config import HTTP_WORKERS, HTTP_TIMEOUT

# Use system CA store for browser-like SSL verification
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass  # Fall back to certifi if truststore not available

# User agent for requests
USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36"

# Known default page title patterns (case-insensitive)
DEFAULT_PAGE_PATTERNS = [
    # IIS defaults only
    "iis windows server",
    "internet information services",
    "iis7",
    "iis8",
    "iis10",
]


def get_certificate_details(hostname: str, port: int = 443) -> dict:
    """
    Get detailed information from SSL certificate.

    Returns:
        dict with cn, issuer, not_after, is_expired, is_self_signed
        or None on error
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)

                try:
                    from cryptography import x509
                    from datetime import datetime, timezone

                    cert = x509.load_der_x509_certificate(cert_der)

                    # Extract CN from subject
                    cn = None
                    for attr in cert.subject:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            cn = attr.value
                            break

                    # Extract issuer CN
                    issuer_cn = None
                    for attr in cert.issuer:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            issuer_cn = attr.value
                            break

                    # Get expiration date
                    not_after = cert.not_valid_after_utc
                    not_before = cert.not_valid_before_utc
                    now = datetime.now(timezone.utc)

                    # Check if expired
                    is_expired = now > not_after
                    is_not_yet_valid = now < not_before

                    # Check if self-signed (subject == issuer)
                    is_self_signed = cert.subject == cert.issuer

                    return {
                        'cn': cn,
                        'issuer': issuer_cn,
                        'not_after': not_after.strftime('%Y-%m-%d'),
                        'not_before': not_before.strftime('%Y-%m-%d'),
                        'is_expired': is_expired,
                        'is_not_yet_valid': is_not_yet_valid,
                        'is_self_signed': is_self_signed,
                    }
                except ImportError:
                    pass

                return None
    except Exception:
        return None


def format_ssl_error(hostname: str, error_str: str) -> str:
    """
    Format SSL error with certificate details.

    Returns:
        Formatted error string with certificate info
    """
    lower_error = error_str.lower()

    # Connection-level SSL errors (no certificate to analyze)
    if 'unexpected_eof' in lower_error or 'eof occurred' in lower_error:
        return 'SSL connection failed'
    if 'connection reset' in lower_error or 'connection refused' in lower_error:
        return 'connection refused'
    if 'timed out' in lower_error or 'timeout' in lower_error:
        return 'connection timeout'

    details = get_certificate_details(hostname)

    # If we can't get certificate details, try with longer timeout
    if not details:
        details = get_certificate_details(hostname, port=443)

    # Still no details - try to extract CN from error message
    if not details:
        # Try to extract CN from error message like: '"*.coral.ru" certificate is not trusted'
        # Note: macOS uses Unicode smart quotes (U+201C and U+201D) instead of regular quotes
        # Don't use single quote as delimiter since it appears in "Let's Encrypt"
        cn_match = re.search(r'[\u201C\u201D"]+([^\u201C\u201D"]+)[\u201C\u201D"]+\s*certificate', error_str)
        extracted_cn = cn_match.group(1) if cn_match else None

        if 'expired' in lower_error:
            if extracted_cn:
                return f'expired: {extracted_cn}'
            return 'expired certificate'
        if 'self signed' in lower_error or 'self-signed' in lower_error:
            if extracted_cn:
                return f'self-signed: {extracted_cn}'
            return 'self-signed certificate'
        if 'hostname mismatch' in lower_error or "doesn't match" in lower_error or 'does not match' in lower_error:
            if extracted_cn:
                return f'different certificate: {extracted_cn}'
            return 'hostname mismatch'
        if 'not trusted' in lower_error:
            if extracted_cn:
                return f'expired: {extracted_cn}'  # "not trusted" usually means expired
            return 'untrusted certificate'
        if 'unknown ca' in lower_error or 'unknown_ca' in lower_error:
            return 'untrusted issuer'
        if 'certificate_verify_failed' in lower_error:
            return 'certificate verification failed'
        return 'SSL error'

    cn = details['cn'] or 'unknown'

    # Hostname mismatch / certificate name does not match
    if 'hostname mismatch' in lower_error or "doesn't match" in lower_error or 'does not match' in lower_error:
        return f"different certificate: {cn}"

    # Expired certificate
    if details['is_expired']:
        return f"expired: {cn} ({details['not_after']})"

    # Not yet valid certificate
    if details['is_not_yet_valid']:
        return f"not yet valid: {cn} (valid from {details['not_before']})"

    # Self-signed certificate
    if details['is_self_signed']:
        return f"self-signed: {cn}"

    # Certificate not trusted (expired CA, revoked, etc.)
    if 'not trusted' in lower_error:
        issuer = details['issuer'] or 'unknown'
        return f"untrusted: {cn} (issuer: {issuer})"

    # Self-signed mentioned in error but not detected (edge case)
    if 'self signed' in lower_error or 'self-signed' in lower_error:
        return f"self-signed: {cn}"

    # Expired mentioned in error but not detected (edge case - clock skew?)
    if 'expired' in lower_error:
        return f"expired: {cn} ({details['not_after']})"

    # Unknown CA / untrusted issuer
    if 'unknown ca' in lower_error or 'unknown_ca' in lower_error or 'unable to get local issuer' in lower_error:
        issuer = details['issuer'] or 'unknown'
        return f"untrusted issuer: {cn} (issuer: {issuer})"

    # Generic certificate verification failed - provide details
    if 'certificate_verify_failed' in lower_error:
        issuer = details['issuer'] or 'unknown'
        if details['is_self_signed']:
            return f"self-signed: {cn}"
        return f"untrusted: {cn} (issuer: {issuer})"

    # Fallback with CN info
    return f"SSL error: {cn}"


def check_status(url: str) -> str:
    """
    Check HTTP status code of a URL.

    Returns:
        Status code as string, or error message
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(
            url,
            headers=headers,
            allow_redirects=False,
            timeout=HTTP_TIMEOUT,
            verify=True
        )
        return str(resp.status_code)
    except requests.exceptions.SSLError as e:
        error_str = str(e)
        parsed = urlparse(url)
        hostname = parsed.hostname
        return format_ssl_error(hostname, error_str)
    except Exception as e:
        return str(e)


def check_default_page(url: str) -> str:
    """
    Check if URL shows IIS default page.

    Returns:
        "True" if IIS default page, "False" otherwise, None on error
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=5, verify=False)

        # Only check HTML pages
        content_type = resp.headers.get('Content-Type', '').lower()
        if 'html' not in content_type:
            return "False"

        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title

        if title is None:
            return "False"

        title_text = title.string if title.string else ""
        title_text = title_text.strip().lower()

        # Only check for IIS default page patterns
        for pattern in DEFAULT_PAGE_PATTERNS:
            if pattern in title_text:
                return "True"

        return "False"
    except Exception:
        return None


def normalize_error(value: str) -> str:
    """
    Normalize error messages for cleaner output.
    """
    if not value:
        return value

    # Already formatted values from format_ssl_error - pass through
    formatted_prefixes = (
        'different certificate:',
        'expired:',
        'not yet valid:',
        'self-signed:',
        'untrusted issuer:',
        'untrusted:',
        'untrusted certificate',
        'SSL error:',
        'SSL connection failed',
    )
    if value.startswith(formatted_prefixes):
        return value

    # Convert to lowercase for easier matching
    lower_value = value.lower()
    
    # === SSL/TLS Errors ===
    if 'key too weak' in lower_value or 'self signed' in lower_value:
        return 'invalid certificate'
    if 'expired' in lower_value:
        return 'expired certificate'
    if 'certificate_verify_failed' in lower_value:
        return 'certificate verification failed'
    if 'wrong_version_number' in lower_value:
        return 'SSL version mismatch'
    if 'tlsv1_alert_protocol_version' in lower_value or 'protocol_version' in lower_value:
        return 'TLS version not supported'
    if 'unsafe_legacy_renegotiation' in lower_value:
        return 'legacy SSL negotiation'
    if 'handshake_failure' in lower_value or 'ssl_handshake' in lower_value:
        return 'SSL handshake failed'
    if 'certificate required' in lower_value:
        return 'client certificate required'
    if 'unknown ca' in lower_value or 'unknown_ca' in lower_value:
        return 'unknown certificate authority'
    if 'certificate revoked' in lower_value or 'revoked' in lower_value:
        return 'certificate revoked'
    if 'hostname mismatch' in lower_value or "doesn't match" in lower_value or 'certificate verify failed' in lower_value and 'hostname' in lower_value:
        return 'hostname mismatch'
    if "doesn't match" in lower_value or ('match' in lower_value and ('certificate' in lower_value or 'hostname' in lower_value)):
        try:
            parts = value.split("match")
            extracted = re.findall(r"(?<=')[^']+(?=')", parts[1])
            if extracted:
                return f"different certificate: {extracted[0]}"
        except:
            pass
    if 'local' in lower_value and 'issuer' in lower_value:
        return 'manual check required'
    
    # === Connection Errors ===
    if any(x in lower_value for x in ['connectionreseterror', 'remotedisconnected', 'failed to establish', 'internal error']):
        return 'Connection Reset'
    if 'name or service not known' in lower_value or 'getaddrinfo failed' in lower_value:
        return 'DNS resolution failed'
    if 'no route to host' in lower_value:
        return 'host unreachable'
    if 'connection refused' in lower_value:
        return 'connection refused'
    if 'network is unreachable' in lower_value:
        return 'network unreachable'
    if 'max retries exceeded' in lower_value:
        return 'max retries exceeded'
    if 'read timed out' in lower_value:
        return 'read timeout'
    if 'connection timed out' in lower_value:
        return 'connection timeout'
    if 'timeout' in lower_value:
        return 'timeout'
    
    # === HTTP Errors ===
    if 'too many redirects' in lower_value or 'exceeded' in lower_value and 'redirect' in lower_value:
        return 'redirect loop'
    if 'badstatusline' in lower_value:
        return 'invalid HTTP response'
    if 'incompleteread' in lower_value:
        return 'incomplete response'
    if 'chunkedencodingerror' in lower_value:
        return 'encoding error'
    
    return value


def check_url(domain: str, ports: str) -> dict:
    """
    Check HTTP and HTTPS status for a domain based on open ports.
    
    Returns:
        dict with http_status, https_status, http_default, https_default
    """
    result = {
        "domain": domain,
        "http_status": None,
        "https_status": None,
        "http_default": None,
        "https_default": None,
    }
    
    if not ports or ports == "null":
        return result
    
    # Check HTTP (port 80)
    if "80 - http" in ports and "*" not in domain:
        url = f"http://{domain}"
        status = check_status(url)
        result["http_status"] = normalize_error(status)
        
        if status == "200":
            result["http_default"] = check_default_page(url)
        else:
            result["http_default"] = "False"
    
    # Check HTTPS (port 443)
    if "443 - http" in ports and "*" not in domain:
        url = f"https://{domain}"
        status = check_status(url)
        result["https_status"] = normalize_error(status)
        
        if status == "200":
            result["https_default"] = check_default_page(url)
        else:
            result["https_default"] = "False"
    
    return result


def check_batch(items: list, progress_callback=None) -> list:
    """
    Check HTTP status for multiple domain/port pairs in parallel.
    
    Args:
        items: List of dicts with 'domain' and 'ports' keys
        progress_callback: Optional callback(completed, total) for progress
    
    Returns:
        List of check results
    """
    results = []
    total = len(items)
    completed = 0
    
    with ThreadPoolExecutor(max_workers=HTTP_WORKERS) as executor:
        futures = {
            executor.submit(check_url, item["domain"], item["ports"]): item 
            for item in items
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            
            if progress_callback:
                progress_callback(completed, total, "http")
            
            print(f"[HTTP] Checked {result['domain']}")
    
    return results
