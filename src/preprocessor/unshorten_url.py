import httpx

"""
URL UNSHORTENER UTILITY
Resolves shortened URLs (e.g., bit.ly, tinyurl) to their true destination.

- Fast & Secure: Uses `follow_redirects=False` to fetch only the HTTP 'Location' 
  header (3xx status), preventing malicious payload execution and saving time.
- Targeted: Only runs on a predefined list of known shortener domains.
- Bypass: Uses a standard browser User-Agent to avoid basic bot blocks.
"""

def unshorten_url(url):
    """
    INPUT:  Raw URL string.
    OUTPUT: Resolved URL (if successful), else returns the original URL.
    """
    short_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rebrand.ly', 'is.gd', 'ow.ly', 'buff.ly']
    
    try:
        domain = url.lower().split('/')[2] if url.startswith('http') else url.lower().split('/')[0]
        domain = domain.replace('www.', '')
        
        if any(sd in domain for sd in short_domains):
            if not url.startswith('http'):
                url = 'http://' + url
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            with httpx.Client(follow_redirects=False, timeout=5.0, headers=headers) as client:
                response = client.get(url)
                
                if response.status_code in (301, 302, 303, 307, 308):
                    final_link = response.headers.get('location')
                    if final_link:
                        return final_link
                        
    except Exception as e:
        print(f"Unshorten Header Error: {e}") 
        
    return url