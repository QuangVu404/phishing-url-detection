import re
import urllib.parse
import base64

'''
TRIẾT LÝ TOKENIZATION:
GIỮ NGUYÊN (model cần học):
  • Path text:  /login /verify /secure /paypal-update → signal phishing
  • Param name: action= type= page= → semantic có nghĩa
  • Param value text: ?action=delete ?type=account → có nghĩa
  • Domain:     giữ toàn bộ (main feature)
  
MASK (model không cần giá trị cụ thể):
  • Token/session/API key ngẫu nhiên: dù ngắn hay dài
  • Numeric ID trong path ≥ 6 chữ số
  • Hash/UUID/JWT
  • Email (với context match/mismatch)
  • IP addresses (kể cả obfuscated)
  • File names (với context exec/macro/id/name)
  • Redirect targets (với context external/internal/encoded)
  • OTP/PIN/passcode codes
  • Base64 values (với context external URL hay không)
'''

# 0. NORMALIZE OBFUSCATED IP
# Anchor ở domain position (trước / ? # :) để tránh false positive
# với numeric ID trong path.
_OBF_DEC_RE = re.compile(r'^(\d{8,10})(?=[:/?#]|$)')
_OBF_HEX_RE = re.compile(r'^(0[xX][0-9a-fA-F]{6,8})(?=[:/?#]|$)')
_OBF_OCT_RE = re.compile(r'^((0[0-7]+\.){3}0[0-7]+)(?=[:/?#]|$)')

def _normalize_obfuscated_ip(url: str) -> str:
    """Chuyển decimal/hex/octal IP → dotted-decimal để IPV4 rule bắt được."""
    m = _OBF_DEC_RE.match(url)
    if m:
        n = int(m.group(1))
        if n <= 0xFFFFFFFF:  # bỏ lower bound — giữ cả 127.0.0.1, 0.x.x.x
            ip = f"{(n>>24)&255}.{(n>>16)&255}.{(n>>8)&255}.{n&255}"
            return ip + url[len(m.group(1)):]
    m = _OBF_HEX_RE.match(url)
    if m:
        n = int(m.group(1), 16)
        if n <= 0xFFFFFFFF:
            ip = f"{(n>>24)&255}.{(n>>16)&255}.{(n>>8)&255}.{n&255}"
            return ip + url[len(m.group(1)):]
    m = _OBF_OCT_RE.match(url)
    if m:
        parts = m.group(1).rstrip('.').split('.')
        if len(parts) == 4:
            try:
                octets = [int(p, 8) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    return '.'.join(str(o) for o in octets) + url[len(m.group(1)):]
            except (ValueError, OverflowError):
                pass
    return url


# 1. HELPER PATTERNS
_SEG_END = r'(?=[&#/?]|$)'   # kết thúc path segment hoặc query
_QS_END  = r'(?=[&#]|$)'    # kết thúc query string param

# Giá trị "ngẫu nhiên" trong query string — dùng cho TOKEN, SESSION, OAUTH
# Nguyên tắc mask:
#   - Thuần số ≥ 4 chữ số           → mask (numeric ID, OTP, timestamp)
#   - Hex ≥ 8 chữ số                → mask (hash rút gọn, secret)
#   - Mix chữ+số ≥ 8 chars          → mask (random token)
#   - Text thuần (abc, true, false) → KHÔNG mask (có nghĩa, giữ lại)
_RANDOM_VALUE = (
    r'('
    r'\d{4,}'
    r'|(?=[^\s&#]*\d)[a-fA-F0-9]{8,}'
    r'|(?=[^\s&#]*[a-zA-Z])(?=[^\s&#]*\d)[a-zA-Z0-9\-_\.=]{8,}'
    r')'
)


# 2. VALUE_BASED_RULES
VALUE_BASED_RULES = {

    # Network addresses — IP là signal phishing mạnh
    '<IPV4>': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    '<IPV6>': re.compile(r'\[?(?:[a-fA-F0-9]{1,4}:){3,7}[a-fA-F0-9]{0,4}\]?'),
    '<MAC_ADDRESS>': re.compile(
        r'(\b)((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})(?=\b)'
    ),

    # Date — giữ pattern ngày, không cần giá trị cụ thể
    '<DATE>': re.compile(
        r'(\b|/)((?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01]))'
        r'(?=\b|/|$)'
    ),

    # Path IDs
    '<NUMERIC_ID>': re.compile(r'(/)(\d{6,})(?=/|[?#]|$)'),
    '<HEX_ID>':     re.compile(r'(/)([\da-fA-F]{15,})(?=/|[?#]|$)'),

    # Crypto wallets
    '<ETH_WALLET>': re.compile(r'(\b)(0x[\da-fA-F]{40})(?=\b)'),
    '<BTC_WALLET>': re.compile(
        r'([?&/=])(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})'
        + _SEG_END
    ),

    # Query + path — specific trước general
    '<UUID_FORMAT>': re.compile(
        r'([?&][^=]+=|/)(?!<)'
        r'([\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12})'
        + _SEG_END
    ),
    '<JWT_FORMAT>': re.compile(
        r'([?&][^=]+=|/)(?!<)(eyJ[\w-]+\.[\w-]+\.[\w-]+)' + _SEG_END
    ),
    # HASH trước BASE64 — hex 32/40/64 chars bị BASE64 snatch nếu để sau
    '<HASH_FORMAT>': re.compile(
        r'([?&][^=]+=|/)(?!<)'
        r'([\da-fA-F]{32}|[\da-fA-F]{40}|[\da-fA-F]{64})' + _SEG_END
    ),

    # Email trong query param
    '<EMAIL>': re.compile(
        r'([?&][^=]+=)(?!<)([\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,})' + _QS_END
    ),

    # BASE64 — đơn giản hóa khỏi double-lookahead, threshold {20,}
    # Lý do bỏ double-lookahead: base64('http://evil.com') = 'aHR0cDovL2V2aWwuY29t'
    # có uppercase nhưng base64 binary thuần sẽ bị miss
    '<BASE64_FORMAT>': re.compile(
        r'([?&][^=]+=)(?!<)([\w+/\-]{20,}={0,2})' + _QS_END
    ),
}

# 3. NAME_BASED_RULES
NAME_BASED_RULES = {

    # Session — luôn mask vì không bao giờ có nghĩa semantic
    '<SESSION_ID>': re.compile(
        r'([?&](?:session|sid|sessionid|PHPSESSID|JSESSIONID)=)(?!<)'
        + _RANDOM_VALUE + _QS_END,
        re.IGNORECASE
    ),

    # Token/API key — mask mọi giá trị random (kể cả ngắn)
    '<TOKEN>': re.compile(
        r'([?&](?:token|access_token|auth|api_key|key|secret|bearer)=)(?!<)'
        + _RANDOM_VALUE + _QS_END,
        re.IGNORECASE
    ),

    # OTP / PIN / passcode — thêm mới
    # Đây là numeric code ngắn — dễ bị model học thuộc lòng nếu không mask
    # Mask với tag riêng để model biết đây là authentication code
    '<OTP_CODE>': re.compile(
        r'([?&](?:otp|pin|passcode|verification_code|confirm_code|'
        r'verif_code|2fa|mfa|one_time_password|auth_code)=)(?!<)'
        r'(\d{4,8})'  # chỉ mask numeric code 4-8 chữ số
        + _QS_END,
        re.IGNORECASE
    ),

    # OAuth params
    '<OAUTH_PARAM>': re.compile(
        r'([?&](?:code|state|nonce|sig|signature)=)(?!<)'
        + _RANDOM_VALUE + _QS_END,
        re.IGNORECASE
    ),
    '<OAUTH_CLIENT>': re.compile(
        r'([?&](?:client_id|app_id|consumer_key)=)(?!<)'
        + _RANDOM_VALUE + _QS_END,
        re.IGNORECASE
    ),

    # Timestamp — mask numeric, giữ text
    '<TIMESTAMP>': re.compile(
        r'([?&](?:timestamp|ts|time|date|t|_t)=)(?!<)'
        r'(\d{8,15}'
        r'|(?:19|20)\d{2}[-/.T](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])'
        r'(?:[T ]\d{2}:\d{2}(?::\d{2})?)?'
        r')' + _QS_END,
        re.IGNORECASE
    ),

    # IP trong query string
    '<IP_PARAM>': re.compile(
        r'([?&](?:ip|ip_address|remote_addr|client_ip)=)(?!<)'
        r'(localhost'
        r'|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        r'|(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{0,4}'
        r'|\d{7,10}'
        r')' + _QS_END,
        re.IGNORECASE
    ),

    # Generic ID — numeric hoặc hex trong query
    '<ID>': re.compile(
        r'([?&](?:id|uid|[a-z_]*_id)=)(?!<)'
        r'(\d{4,}|(?=[^\s&#]*\d)[a-fA-F0-9]{10,})' + _QS_END,
        re.IGNORECASE
    ),

    # Catch-all: REF và FILE_PARAM để cuối vì [^&#]* quá rộng
    # Đặt sau tất cả specific rules để không snatch giá trị của SESSION/TOKEN
    '<REF>': re.compile(
        r'([?&](?:ref|reference|referrer|returnUrl|next|redirect|redirect_uri|'
        r'url|return|goto|dest|destination)=)(?!<)([^&#]*)',
        re.IGNORECASE
    ),
    '<FILE_PARAM>': re.compile(
        r'([?&](?:file|doc|document|download|dl|attachment|attach|asset)=)(?!<)'
        r'([^&#]*)',
        re.IGNORECASE
    ),
}

# Thứ tự VALUE_BASED — specific trước general, HASH trước BASE64
_VALUE_ORDER = [
    '<MAC_ADDRESS>', '<ETH_WALLET>', '<BTC_WALLET>',
    '<UUID_FORMAT>', '<JWT_FORMAT>',
    '<HASH_FORMAT>',       # ← TRƯỚC BASE64
    '<EMAIL>',
    '<HEX_ID>', '<NUMERIC_ID>',
    '<BASE64_FORMAT>',     # ← catch-all cuối
]


# 4. CLASSIFIER HELPERS

# REF classifier
_EXTERNAL_SCHEME_RE = re.compile(
    r'^(?:https?://|//|javascript:|data:|vbscript:|\\/?/)', re.IGNORECASE
)
_ENCODED_EXT_RE = re.compile(
    r'(?:https?%3A|%2F%2F|javascript%3A)', re.IGNORECASE
)
_DOUBLE_ENCODED_RE = re.compile(
    r'(?:https?%253A|%252F%252F|javascript%253A)', re.IGNORECASE
)
_BARE_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:[:/]|$)', re.IGNORECASE
)

# FILE classifier
_EXEC_EXTS = frozenset([
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.wsf', '.hta',
    '.jar', '.class', '.sh', '.bash', '.py', '.rb', '.php',
    '.dll', '.scr', '.pif', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.img',
    '.jse', '.vbe',
])
_MACRO_EXTS = frozenset(['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'])

# EMAIL classifier — ecosystem map
_EMAIL_ECOSYSTEMS = {
    'google':    frozenset(['gmail', 'google', 'googlemail']),
    'gmail':     frozenset(['gmail', 'google', 'googlemail']),
    'microsoft': frozenset(['microsoft', 'outlook', 'live', 'msn', 'hotmail']),
    'outlook':   frozenset(['microsoft', 'outlook', 'live', 'msn', 'hotmail']),
    'live':      frozenset(['microsoft', 'outlook', 'live', 'msn', 'hotmail']),
    'office':    frozenset(['microsoft', 'outlook', 'live', 'msn', 'hotmail']),
    'yahoo':     frozenset(['yahoo']),
    'apple':     frozenset(['icloud', 'apple']),
    'icloud':    frozenset(['icloud', 'apple']),
}


# 5. REPLACER FACTORY 
def get_replacer(mask_tag, url_domain=''):
    """
    Sinh ra hàm replacer cho từng mask_tag.
    url_domain: domain URL gốc, dùng cho EMAIL classifier.
    """
    base_tag = mask_tag[1:-1]

    def replacer(match):
        prefix = match.group(1)
        target = match.group(2)
        n = len(target)

        # Giá trị rỗng
        if not target:
            return f"{prefix}<{base_tag}_EMPTY>"

        # REF: phân loại redirect target
        # Đây là attack vector số 1. Model cần phân biệt:
        #   REF_EXTERNAL  = chuyển hướng ra ngoài → nguy hiểm
        #   REF_ENCODED   = obfuscated redirect   → rất nguy hiểm
        #   REF_INTERNAL  = chuyển hướng nội bộ   → bình thường
        #   REF_DOMAIN    = domain không scheme    → đáng ngờ
        #   REF_OTHER     = keyword/text           → bình thường
        if mask_tag == '<REF>':
            decoded = urllib.parse.unquote(target).strip()
            if '%' in decoded:
                decoded = urllib.parse.unquote(decoded).strip()
            if _ENCODED_EXT_RE.search(target) or _DOUBLE_ENCODED_RE.search(target):
                tag = f"REF_ENCODED_{n}"
            elif _EXTERNAL_SCHEME_RE.match(decoded):
                tag = f"REF_EXTERNAL_{n}"
            elif decoded.startswith('/'):
                tag = f"REF_INTERNAL_{n}"
            elif _BARE_DOMAIN_RE.match(decoded):
                tag = f"REF_DOMAIN_{n}"
            else:
                tag = f"REF_OTHER_{n}"
            return f"{prefix}<{tag}>"

        # BASE64: decode để phát hiện URL ẩn
        # Hacker encode "http://evil.com" → base64 để qua filter.
        # Chỉ check external scheme, không check bare domain (false positive cao).
        if mask_tag == '<BASE64_FORMAT>':
            try:
                padded = target + '=' * (-len(target) % 4)
                decoded_b64 = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if _EXTERNAL_SCHEME_RE.match(decoded_b64.strip()):
                    return f"{prefix}<BASE64_EXTERNAL_{n}>"
            except Exception:
                pass
            return f"{prefix}<BASE64_FORMAT_{n}>"

        # EMAIL: MATCH vs MISMATCH với URL domain
        # Hacker nhét email nạn nhân vào URL để form login hiện sẵn email.
        # EMAIL_MISMATCH = email domain ≠ URL domain → personalization phishing.
        if mask_tag == '<EMAIL>':
            email_domain = target.split('@')[-1].lower() if '@' in target else ''
            url_main  = '.'.join(url_domain.split('.')[-2:]).lower() if url_domain else ''
            email_main = '.'.join(email_domain.split('.')[-2:])
            is_match = (email_main == url_main)
            if not is_match:
                for url_kw, email_kws in _EMAIL_ECOSYSTEMS.items():
                    if url_kw in url_domain and any(k in email_domain for k in email_kws):
                        is_match = True
                        break
            tag = f"EMAIL_MATCH_{n}" if is_match else f"EMAIL_MISMATCH_{n}"
            return f"{prefix}<{tag}>"

        # FILE_PARAM: phân loại file nguy hiểm
        # Hacker dùng Drive/Dropbox/SharePoint để phân phối malware.
        # Model cần biết: FILE_EXEC/MACRO = malware delivery signal.
        if mask_tag == '<FILE_PARAM>':
            lower_v = target.lower()
            ext = ''
            if '.' in lower_v:
                ext = '.' + re.sub(r'[?&#].*', '', lower_v.rsplit('.', 1)[-1])
            if ext in _EXEC_EXTS:
                tag = f"FILE_EXEC_{n}"
            elif ext in _MACRO_EXTS:
                tag = f"FILE_MACRO_{n}"
            elif not ext and re.match(r'^[a-zA-Z0-9_\-]{8,}$', target):
                tag = f"FILE_ID_{n}"   # Drive ID, S3 key
            else:
                tag = f"FILE_NAME_{n}"
            return f"{prefix}<{tag}>"

        # Default: mask với độ dài
        return f"{prefix}<{base_tag}_{n}>"

    return replacer


# 6. STATIC REPLACER CACHE
_STATIC_REPLACERS = {'<DATE>': get_replacer('<DATE>')}

for _tag in _VALUE_ORDER:
    if _tag != '<EMAIL>':
        _STATIC_REPLACERS[_tag] = get_replacer(_tag)

for _tag in NAME_BASED_RULES:
    _STATIC_REPLACERS[_tag] = get_replacer(_tag)


# 7. SANITIZE_URL
def sanitize_url(url):
    """
    Mask các giá trị nhạy cảm trong URL → typed semantic tags.

    GIỮ NGUYÊN: path keywords (/login /verify), param names, text values
    MASK:        random values, IDs, tokens, emails, IPs, files, redirects

    INPUT:  URL đã qua clean_url() (lowercase, no protocol, no www)
    OUTPUT: URL với masked values
    """
    if not isinstance(url, str) or len(url) < 10:
        return url

    # Step 0: Normalize obfuscated IP ở domain position
    masked = _normalize_obfuscated_ip(url)

    # Extract domain cho EMAIL classifier (trước khi bất kỳ rule nào chạy)
    url_domain = masked.split('/')[0].split('?')[0].split('#')[0]

    # Step 1: IP addresses (sau normalize)
    masked = VALUE_BASED_RULES['<IPV4>'].sub('<IP_ADDRESS>', masked)
    masked = VALUE_BASED_RULES['<IPV6>'].sub('<IP_ADDRESS>', masked)

    # Step 2: DATE — sớm, trước NUMERIC_ID snatch
    masked = VALUE_BASED_RULES['<DATE>'].sub(_STATIC_REPLACERS['<DATE>'], masked)

    # Step 3: Value-based rules theo _VALUE_ORDER (specific → general)
    for mask_tag in _VALUE_ORDER:
        replacer = get_replacer(mask_tag, url_domain) if mask_tag == '<EMAIL>' \
                   else _STATIC_REPLACERS[mask_tag]
        masked = VALUE_BASED_RULES[mask_tag].sub(replacer, masked)

    # Step 4: Name-based rules
    for mask_tag, pattern in NAME_BASED_RULES.items():
        masked = pattern.sub(_STATIC_REPLACERS[mask_tag], masked)

    return masked