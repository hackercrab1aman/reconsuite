import re
import time
import socket
import ipaddress
import logging
import functools
from urllib.parse import urlparse, urljoin

# Configure logging
logger = logging.getLogger(__name__)

def rate_limit(seconds):
    """Decorator to rate limit function calls"""
    def decorator(func):
        last_called = [0.0]  # Use list to maintain state between calls
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            if elapsed < seconds:
                time.sleep(seconds - elapsed)
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result
        return wrapper
    return decorator

def validate_domain(domain):
    """Validate if a string is a valid domain name"""
    # Check if it's an IP address
    if is_valid_ip(domain):
        return True
    
    # Domain validation regex
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(pattern, domain):
        return True
    
    # URL validation - extract domain from URL
    try:
        parsed = urlparse(domain)
        if parsed.netloc:
            # Extract domain from netloc
            domain = parsed.netloc
            if ':' in domain:  # Remove port if present
                domain = domain.split(':')[0]
            return re.match(pattern, domain) is not None
        elif parsed.path and '.' in parsed.path and not parsed.scheme:
            # Handle cases like "example.com/path"
            potential_domain = parsed.path.split('/')[0]
            return re.match(pattern, potential_domain) is not None
    except Exception:
        return False
    
    return False

def is_valid_ip(ip):
    """Check if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sanitize_input(input_str):
    """Sanitize user input to prevent command injection"""
    if not input_str:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;&|`$(){}]', '', input_str)
    return sanitized.strip()

def sanitize_url(url):
    """Ensure URL has proper scheme and format"""
    if not url:
        return ""
    
    url = url.strip()
    
    # Check if URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        # Reconstruct URL to ensure it's well-formed
        reconstructed = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            reconstructed += f"?{parsed.query}"
        return reconstructed
    except Exception as e:
        logger.error(f"Error sanitizing URL {url}: {str(e)}")
        return url

def extract_hostname(url):
    """Extract hostname from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return url

def is_same_domain(url1, url2):
    """Check if two URLs belong to the same domain"""
    try:
        host1 = urlparse(url1).netloc
        host2 = urlparse(url2).netloc
        
        # Remove port if present
        if ':' in host1:
            host1 = host1.split(':')[0]
        if ':' in host2:
            host2 = host2.split(':')[0]
        
        # Check if domains match
        return host1 == host2
    except Exception:
        return False

def get_domain_variations(domain):
    """Generate variations of a domain for subdomain enumeration"""
    parts = domain.split('.')
    if len(parts) < 2:
        return [domain]
    
    tld = '.'.join(parts[-2:])  # e.g., example.com
    if len(parts) == 2:
        return [domain]
    else:
        return [domain, tld]
