import tldextract

import Levenshtein as lv

# List of known safe domains
safe_domains = [
    "google.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com"
]

def is_phishing(url):
    # Extract domain from the URL
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    # Check against known safe domains
    for safe_domain in safe_domains:
        # Calculate similarity score
        score = lv.ratio(domain, safe_domain)
        # If similarity is above 0.8, it might be a phishing attempt
        if score > 0.8:
            return False

    # If no match found, consider it suspicious
    return True

# Example usage
urls = [
    "https://www.gooogle.com",
    "https://www.facebo0k.com",
    "https://www.example.com"
]

for url in urls:
    if is_phishing(url):
        print(f"{url} might be a phishing link.")
    else:
        print(f"{url} appears to be safe.")