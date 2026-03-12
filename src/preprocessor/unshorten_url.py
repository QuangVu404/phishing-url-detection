import httpx

def unshorten_url(url):
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