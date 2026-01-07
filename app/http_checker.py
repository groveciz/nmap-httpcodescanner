"""
HTTP/HTTPS Status Checker Module
"""
import requests
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.config import HTTP_WORKERS, HTTP_TIMEOUT

# User agent for requests
USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36"

# Known default page title patterns (case-insensitive)
DEFAULT_PAGE_PATTERNS = [
    # Apache defaults
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "test page for the apache",
    "it works!",
    
    # Nginx defaults
    "welcome to nginx",
    
    # IIS defaults
    "iis windows server",
    "internet information services",
    "iis7", "iis8", "iis10",
    
    # Generic hosting/placeholder pages
    "web server's default page",
    "index of /",
    "directory listing",
    "welcome to",
    "congratulations",
    "under construction",
    "coming soon",
    "site under maintenance",
    "maintenance mode",
    "parked domain",
    "this domain",
    "domain for sale",
    "website coming soon",
    "new website",
    "placeholder",
    "default web site page",
    "default page",
    
    # Hosting provider defaults
    "plesk", "cpanel", "webmin", "directadmin",
    
    # Generic
    "test page",
    "example domain",
]


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
    except Exception as e:
        return str(e)


def check_default_page(url: str) -> str:
    """
    Check if URL shows a default/placeholder page.
    
    Returns:
        "True" if default page, "False" otherwise, None on error
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title
        
        # No title = likely default page
        if title is None:
            return "True"
        
        title_text = title.string if title.string else ""
        title_text = title_text.strip().lower()
        
        if not title_text:
            return "True"
        
        # Check against patterns
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
    
    if any(x in value for x in ['ConnectionResetError', 'RemoteDisconnected', 'Failed to establish', 'internal error']):
        return 'Connection Reset'
    if 'key too weak' in value or 'self signed' in value:
        return 'invalid certificate'
    if 'expired' in value:
        return 'expired certificate'
    if 'timeout' in value:
        return 'timeout'
    if 'match' in value:
        try:
            parts = value.split("match")
            extracted = re.findall(r"(?<=')[^']+(?=')", parts[1])
            if extracted:
                return f"different certificate: {extracted[0]}"
        except:
            pass
    if 'local' in value:
        return 'manual check required'
    
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
