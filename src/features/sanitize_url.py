import re
import urllib.parse
import base64
import binascii

"""
URL SANITIZATION & TOKENIZATION MODULE

Purpose: Masks sensitive, random, or obfuscated components in a URL into 
semantic tags (e.g., <IP_ADDRESS>, <SESSION_ID>, <REF_EXTERNAL>) while 
keeping the core structure and semantic keywords intact for the model.

Key Mechanics:
- Keeps semantic paths/params (/login, ?action=delete) and domains.
- Masks random IDs, Hex/Base64 strings, IPs, Tokens, and Emails.
- Uses contextual replacing (e.g., checking if an email domain matches the URL domain).
- Prevents tag-snatching with strict regex lookarounds and ordered processing.
"""

_OBF_DEC_RE = re.compile(r'^(\d{8,10})(?=[:/?#]|$)')
_OBF_HEX_RE = re.compile(r'^(0[xX][0-9a-fA-F]{6,8})(?=[:/?#]|$)')
_OBF_OCT_RE = re.compile(r'^((0[0-7]+\.){3}0[0-7]+)(?=[:/?#]|$)')

def _normalize_obfuscated_ip(url: str) -> str:
    """Converts obfuscated decimal/hex/octal IPs to dotted-decimal format."""
    m = _OBF_DEC_RE.match(url)
    if m:
        n = int(m.group(1))
        if n <= 0xFFFFFFFF:  
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


_SEG_END = r'(?=[&#/?]|$)'   
_QS_END  = r'(?=[&#]|$)'    

_RANDOM_VALUE = (
    r'('
    r'\d{4,}'
    r'|(?=[^\s&#]*\d)[a-fA-F0-9]{8,}'
    r'|(?=[^\s&#]*[a-zA-Z])(?=[^\s&#]*\d)[a-zA-Z0-9\-_\.=]{8,}'
    r')'
)


VALUE_BASED_RULES = {
    '<IPV4>': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    '<IPV6>': re.compile(r'\[?(?:[a-fA-F0-9]{1,4}:){3,7}[a-fA-F0-9]{0,4}\]?'),
    '<MAC_ADDRESS>': re.compile(
        r'(\b)((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})(?=\b)'
    ),
    '<DATE>': re.compile(
        r'(\b|/)((?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01]))'
        r'(?=\b|/|$)'
    ),
    '<NUMERIC_ID>': re.compile(r'(/)(?!<)(\d{6,})(?=/|[?#]|$)'),
    '<HEX_ID>':     re.compile(r'(/)(?!<)([\da-fA-F]{15,})(?=/|[?#]|$)'),
    '<ETH_WALLET>': re.compile(r'(\b)(0x[\da-fA-F]{40})(?=\b)'),
    '<BTC_WALLET>': re.compile(
        r'([?&/=])(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})'
        + _SEG_END
    ),
    '<UUID_FORMAT>': re.compile(
        r'([?&][^=]+=|/)(?!<)'
        r'([\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12})'
        + _SEG_END
    ),
    '<JWT_FORMAT>': re.compile(
        r'([?&][^=]+=|/)(?!<)(eyJ[\w-]+\.[\w-]+\.[\w-]+)' + _SEG_END
    ),
    '<HASH_FORMAT>': re.compile(
        r'([?&][^=]+=|/)(?!<)'
        r'([\da-fA-F]{32}|[\da-fA-F]{40}|[\da-fA-F]{64})' + _SEG_END
    ),
    '<EMAIL>': re.compile(
        r'([?&][^=]+=)(?!<)([\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,})' + _QS_END
    ),
    '<BASE64_FORMAT>': re.compile(
        r'([?&][^=]+=)(?!<)([\w+/\-]{20,}={0,2})' + _QS_END
    ),
}

NAME_BASED_RULES = {
    '<SESSION_ID>': re.compile(
        r'([?&](?:session|sid|sessionid|PHPSESSID|JSESSIONID)=)(?!<)'
        + _RANDOM_VALUE + _QS_END,
        re.IGNORECASE
    ),
    '<TOKEN>': re.compile(
        r'([?&](?:token|access_token|auth|api_key|key|secret|bearer)=)(?!<)'
        + _RANDOM_VALUE + _QS_END,
        re.IGNORECASE
    ),
    '<OTP_CODE>': re.compile(
        r'([?&](?:otp|pin|passcode|verification_code|confirm_code|'
        r'verif_code|2fa|mfa|one_time_password|auth_code)=)(?!<)'
        r'(\d{4,8})' 
        + _QS_END,
        re.IGNORECASE
    ),
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
    '<TIMESTAMP>': re.compile(
        r'([?&](?:timestamp|ts|time|date|t|_t)=)(?!<)'
        r'(\d{8,15}'
        r'|(?:19|20)\d{2}[-/.T](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])'
        r'(?:[T ]\d{2}:\d{2}(?::\d{2})?)?'
        r')' + _QS_END,
        re.IGNORECASE
    ),
    '<IP_PARAM>': re.compile(
        r'([?&](?:ip|ip_address|remote_addr|client_ip)=)(?!<)'
        r'(localhost'
        r'|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        r'|(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{0,4}'
        r'|\d{7,10}'
        r')' + _QS_END,
        re.IGNORECASE
    ),
    '<ID>': re.compile(
        r'([?&](?:id|uid|[a-z_]*_id)=)(?!<)'
        r'(\d{4,}|(?=[^\s&#]*\d)[a-fA-F0-9]{10,})' + _QS_END,
        re.IGNORECASE
    ),
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

_VALUE_ORDER = [
    '<MAC_ADDRESS>', '<ETH_WALLET>', '<BTC_WALLET>',
    '<UUID_FORMAT>', '<JWT_FORMAT>',
    '<HASH_FORMAT>',       
    '<EMAIL>',
    '<HEX_ID>', '<NUMERIC_ID>',
    '<BASE64_FORMAT>',     
]

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

_EXEC_EXTS = frozenset([
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.wsf', '.hta',
    '.jar', '.class', '.sh', '.bash', '.py', '.rb', '.php',
    '.dll', '.scr', '.pif', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.img',
    '.jse', '.vbe',
])
_MACRO_EXTS = frozenset(['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'])

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


def get_replacer(mask_tag, url_domain=''):
    """Returns a contextual regex replacer based on the mask_tag."""
    base_tag = mask_tag[1:-1]

    def replacer(match):
        prefix = match.group(1)
        target = match.group(2)
        n = len(target)

        if not target:
            return f"{prefix}<{base_tag}_EMPTY>"

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

        if mask_tag == '<BASE64_FORMAT>':
            try:
                padded = target + '=' * (-len(target) % 4)
                decoded_b64 = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if _EXTERNAL_SCHEME_RE.match(decoded_b64.strip()):
                    return f"{prefix}<BASE64_EXTERNAL_{n}>"
            except (UnicodeDecodeError, binascii.Error):
                pass
            return f"{prefix}<BASE64_FORMAT_{n}>"

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
                tag = f"FILE_ID_{n}"   
            else:
                tag = f"FILE_NAME_{n}"
            return f"{prefix}<{tag}>"

        return f"{prefix}<{base_tag}_{n}>"

    return replacer


_STATIC_REPLACERS = {'<DATE>': get_replacer('<DATE>')}

for _tag in _VALUE_ORDER:
    if _tag != '<EMAIL>':
        _STATIC_REPLACERS[_tag] = get_replacer(_tag)

for _tag in NAME_BASED_RULES:
    _STATIC_REPLACERS[_tag] = get_replacer(_tag)


def sanitize_url(url):
    """
    INPUT:  Cleaned URL string (lowercase, no protocol, no www prefix).
    OUTPUT: Masked URL string with sensitive/random values replaced by tags.
    """
    if not isinstance(url, str) or len(url) < 10:
        return url
    
    masked = _normalize_obfuscated_ip(url)

    raw_domain = masked.split('/')[0].split('?')[0].split('#')[0]
    url_domain = raw_domain.split(':')[0] if not raw_domain.startswith('[') else raw_domain

    masked = VALUE_BASED_RULES['<IPV4>'].sub('<IP_ADDRESS>', masked)
    masked = VALUE_BASED_RULES['<IPV6>'].sub('<IP_ADDRESS>', masked)
    masked = VALUE_BASED_RULES['<DATE>'].sub(_STATIC_REPLACERS['<DATE>'], masked)

    for mask_tag in _VALUE_ORDER:
        replacer = get_replacer(mask_tag, url_domain) if mask_tag == '<EMAIL>' \
                   else _STATIC_REPLACERS[mask_tag]
        masked = VALUE_BASED_RULES[mask_tag].sub(replacer, masked)

    for mask_tag, pattern in NAME_BASED_RULES.items():
        masked = pattern.sub(_STATIC_REPLACERS[mask_tag], masked)

    return masked