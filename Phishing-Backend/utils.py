import re
from urllib.parse import urlparse
import tldextract
import numpy as np
import math # For entropy calculation

# Common phishing keywords - good to keep and expand if you find more
PHISHING_KEYWORDS = ['login', 'secure', 'bank', 'update', 'verify', 'account', 'webscr', 'confirm',
                     'signin', 'password', 'free', 'gift', 'award', 'alert', 'error', 'invoice']

# Suspicious TLDs often used in phishing - expanded list
SUSPICIOUS_TLDS = ['.zip', '.review', '.country', '.kim', '.cricket', '.science', '.work', '.party', '.gq',
                   '.top', '.xyz', '.site', '.online', '.club', '.biz', '.info', '.ws', '.cc', '.ga', '.tk', '.ml', '.cf']

# Common URL shortening services
URL_SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'buff.ly', 'is.gd', 's.id']

def calculate_entropy(s):
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    total_chars = len(s)
    for char_freq in freq.values():
        probability = char_freq / total_chars
        entropy -= probability * math.log2(probability)
    return entropy

def extract_features(url):
    features = []

    # --- Initial URL processing ---
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    fragment = parsed.fragment.lower()
    ext = tldextract.extract(url)

    # --- Length-based features ---
    features.append(len(url)) # Total URL length
    features.append(url.count('-')) # Number of hyphens
    features.append(url.count('@')) # Presence of '@' symbol
    features.append(url.count('//')) # Number of double slashes (more than one can be suspicious)

    # --- Protocol and Security ---
    features.append(1 if parsed.scheme == 'https' else 0) # Uses HTTPS
    
    # --- Domain-based features ---
    features.append(hostname.count('.')) # Number of dots in hostname
    
    # IP address in hostname
    is_ip_address = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
    features.append(1 if is_ip_address else 0)

    # Suspicious TLD
    tld = f".{ext.suffix}"
    features.append(1 if tld in SUSPICIOUS_TLDS else 0)

    # Number of subdomains (e.g., www.sub.domain.com -> 2 subdomains)
    subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
    features.append(len(subdomain_parts))

    # URL Shortening service check
    is_shortened = 0
    for shortener in URL_SHORTENERS:
        if shortener in hostname:
            is_shortened = 1
            break
    features.append(is_shortened)

    # Entropy of the domain (randomness) - higher for generated domains
    features.append(calculate_entropy(ext.domain))

    # --- Path and Query-based features ---
    features.append(len(ext.domain)) # Length of the main domain name
    features.append(len(path)) # Length of the URL path
    features.append(len(query)) # Length of the query string

    # Keyword presence in the *full URL* (hostname + path + query)
    full_url_lower = url.lower()
    for keyword in PHISHING_KEYWORDS:
        features.append(1 if keyword in full_url_lower else 0)

    # Digit and special character counts in the full URL
    features.append(sum(char.isdigit() for char in full_url_lower)) # Number of digits
    features.append(sum(not c.isalnum() and c not in ['.', '/', ':', '?', '=', '&', '#', '-'] for c in full_url_lower)) # Number of other special characters

    # Depth of URL path (number of slashes after domain)
    features.append(path.count('/') - (1 if path.startswith('/') else 0)) # subtract 1 if path starts with a slash

    return np.array(features)