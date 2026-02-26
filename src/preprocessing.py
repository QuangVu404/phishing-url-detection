import re

def clean_url(url: str) -> str:
    url = str(url).lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url

# COMPILED PATTERNS
VALUE_BASED_RULES = {
    # 1. NETWORK ADDRESSES
    '<IPV4>': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    '<IPV6>': re.compile(
        r'\[?(?:[a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}\]?'
    ),
    '<MAC_ADDRESS>': re.compile(
        r'(\b)((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})(?=\b)'
    ),
    
    # 2. TIME & DATE
    '<DATE>': re.compile(
        r'(\b|/)((?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01]))'
        r'(?=\b|/|$)'
    ),

    # 3. IDs IN PATH
    '<NUMERIC_ID>': re.compile(r'(/)(\d{6,})(?=/|[?#]|$)'),
    '<HEX_ID>': re.compile(r'(/)([\da-fA-F]{15,})(?=/|[?#]|$)'),

    # 4. CRYPTO WALLETS
    '<ETH_WALLET>': re.compile(r'(\b)(0x[\da-fA-F]{40})(?=\b)'),
    '<BTC_WALLET>': re.compile(r'(\b)([13][\da-km-zA-HJ-NP-Z]{25,34})(?=\b)'),
    
    # 5. QUERY STRING PARAMETERS
    '<UUID_FORMAT>': re.compile(
        r'([?&][^=]+=)([\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-'
        r'[\da-fA-F]{4}-[\da-fA-F]{12})(?=[&#]|$)'
    ),
    '<JWT_FORMAT>': re.compile(r'([?&][^=]+=)(eyJ[\w-]+\.[\w-]+\.[\w-]+)(?=[&#]|$)'),
    '<BASE64_FORMAT>': re.compile(r'([?&][^=]+=)([\w+/\-]{30,}={0,2})(?=[&#]|$)'),
    '<HASH_FORMAT>': re.compile(r'([?&][^=]+=)([\da-fA-F]{32}|[\da-fA-F]{40}|[\da-fA-F]{64})(?=[&#]|$)'),
    '<EMAIL>': re.compile(r'([?&][^=]+=)([\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,})(?=[&#]|$)'),
}

NAME_BASED_RULES = {
    '<ID>': re.compile(r'([?&](?:id|uid|user_id|account_id)=)([^&#<]+)', flags=re.IGNORECASE),
    '<SESSION_ID>': re.compile(r'([?&](?:session|sid|sessionid|PHPSESSID|JSESSIONID)=)([^&#<]+)', flags=re.IGNORECASE),
    '<TOKEN>': re.compile(r'([?&](?:token|access_token|auth|api_key|key)=)([^&#<]+)', flags=re.IGNORECASE),
    '<TIMESTAMP>': re.compile(r'([?&](?:timestamp|ts|time|t|_t)=)([^&#<]+)', flags=re.IGNORECASE),
    '<REF>': re.compile(r'([?&](?:ref|reference|referrer|returnUrl|next|redirect)=)([^&#<]+)', flags=re.IGNORECASE),
    '<OAUTH_PARAM>': re.compile(r'([?&](?:code|state|nonce|sig|signature)=)([^&#<]+)', flags=re.IGNORECASE),
    '<IP_PARAM>': re.compile(r'([?&](?:ip|ip_address|remote_addr|client_ip)=)([^&#<]+)', flags=re.IGNORECASE),
}

# HÀM SANITIZE CHÍNH

def get_length_replacer(mask_tag):
    """
    Hàm sinh ra một hàm replace động.
    Ví dụ: mask_tag = '<HEX_ID>'
    Kết quả replace sẽ là: Nhóm 1 (tiền tố) + '<HEX_ID_ĐộDài>'
    """
    base_tag = mask_tag[1:-1] # Cắt bỏ ngoặc < > để lấy chữ 'HEX_ID'
    
    def replacer(match):
        prefix = match.group(1)   # Ví dụ: '/' hoặc '?id='
        target = match.group(2)   # Ví dụ: đoạn mã Hex thực tế
        length = len(target)      # Đo độ dài đoạn mã
        return f"{prefix}<{base_tag}_{length}>"
        
    return replacer

def sanitize_url(url):
    """
    Sanitize URL by masking sensitive parameters AND tracking their lengths
    """
    if not isinstance(url, str):
        return url
        
    if not url or len(url) < 10:
        return url
        
    masked_url = url

    # STEP 1: Unify IP addresses 
    masked_url = VALUE_BASED_RULES['<IPV4>'].sub('<IP_ADDRESS>', masked_url)
    masked_url = VALUE_BASED_RULES['<IPV6>'].sub('<IP_ADDRESS>', masked_url)

    # STEP 2: Process DATE first (Đo độ dài ngày tháng)
    masked_url = VALUE_BASED_RULES['<DATE>'].sub(get_length_replacer('<DATE>'), masked_url)

    # STEP 3: Other value-based patterns
    for mask_tag, compiled_pattern in VALUE_BASED_RULES.items():
        if mask_tag in ['<IPV4>', '<IPV6>', '<DATE>']:
            continue
        masked_url = compiled_pattern.sub(get_length_replacer(mask_tag), masked_url)
        
    # STEP 4: Name-based patterns
    for mask_tag, compiled_pattern in NAME_BASED_RULES.items():
        masked_url = compiled_pattern.sub(get_length_replacer(mask_tag), masked_url)
        
    return masked_url