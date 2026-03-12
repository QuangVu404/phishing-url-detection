import re

# Remove protocol and www for consistent domain extraction
def clean_url(url: str) -> str:
    url = str(url).lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url