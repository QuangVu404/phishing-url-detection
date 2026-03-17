import os
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences

from src.preprocessor.clean_url import clean_url
from src.preprocessor.unshorten_url import unshorten_url
from src.features.calculate_url_entropy import calculate_entropy
from src.features.sanitize_url import sanitize_url
from src.inference.model_loader import get_model
from src.inference.tokenizer_loader import get_tokenizer
from src.inference.config import MAX_LEN, THRESHOLD, TRANCO_FILE_PATH

"""
URL PREDICTION INFERENCE PIPELINE

1. Unshorten URL (resolve short links).
2. Clean & Normalize (remove protocol, www).
3. Extract Domain & Calculate Entropy.
4. Sanitize (mask sensitive/random data).
5. Tokenize & Pad Sequence.
6. Predict using ResNet1D-SE Model.
7. Apply Heuristics:
   - Penalty: Reduce risk by 40% if main domain is in Trusted Whitelist.
   - Boost: Increase risk by 10% if domain entropy > 4.5.
   
Note: Uses Lazy Singleton Pattern to load resources only once.
Call `init_resources()` during app startup (e.g., FastAPI lifespan).
"""

_model = None
_tokenizer = None
_trusted_domains: frozenset = None

ABUSED_SUBDOMAINS = frozenset({
    "sites.google.com", "docs.google.com", "github.io",
    "netlify.app", "herokuapp.com", "storage.googleapis.com",
    "firebaseapp.com", "web.app",
})

def _load_trusted_domains() -> frozenset:
    """Loads Tranco Top-1M domains + default whitelist into memory."""
    base = {
        "kaggle.com", "google.com", "github.com",
        "microsoft.com", "apple.com",
    }
    if os.path.exists(TRANCO_FILE_PATH):
        try:
            df = pd.read_csv(TRANCO_FILE_PATH, header=None)
            base.update(df[1].astype(str).str.lower().tolist())
            print(f"[*] Loaded {len(base):,} domains into Whitelist.")
        except Exception as e:
            print(f"[!] Error loading Tranco list: {e}")
    else:
        print("[!] Tranco list not found. Using default Whitelist.")
    return frozenset(base)

def init_resources():
    """Pre-warms model, tokenizer, and domains. Call once at startup."""
    global _model, _tokenizer, _trusted_domains
    _model           = get_model()
    _tokenizer       = get_tokenizer()
    _trusted_domains = _load_trusted_domains()

def _get_resources():
    """Lazy initialization: Loads resources if not already loaded."""
    global _model, _tokenizer, _trusted_domains
    if _model is None:
        _model = get_model()
    if _tokenizer is None:
        _tokenizer = get_tokenizer()
    if _trusted_domains is None:
        _trusted_domains = _load_trusted_domains()
    return _model, _tokenizer, _trusted_domains

def predict_phishing(raw_url: str) -> dict:
    """
    Predicts whether a given URL is phishing or legitimate.
    INPUT:  Raw URL string.
    OUTPUT: Dictionary containing prediction result, probability, and metadata.
    """
    raw_url = str(raw_url).strip()
    if len(raw_url) < 4:
        raise ValueError(f"URL too short or empty: {repr(raw_url)}")

    model, tokenizer, trusted_domains = _get_resources()

    resolved = unshorten_url(raw_url)

    url_clean = clean_url(resolved).rstrip("/")
    if not url_clean:
        raise ValueError(f"Invalid URL after cleaning: {repr(raw_url)}")

    domain      = url_clean.split("/")[0]
    main_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain

    domain_entropy = calculate_entropy(domain)

    url_masked = sanitize_url(url_clean)
    seq        = tokenizer.texts_to_sequences([url_masked])
    padded     = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
    prob       = float(model.predict(padded, verbose=0).flatten()[0])

    is_trusted_main     = main_domain in trusted_domains
    is_abused_subdomain = any(domain.endswith(s) for s in ABUSED_SUBDOMAINS)

    # Heuristic Adjustments
    if is_trusted_main and not is_abused_subdomain:
        prob = prob * 0.6
    elif domain_entropy > 4.5:
        prob = min(1.0, prob + 0.1)

    label = "PHISHING" if prob > THRESHOLD else "LEGIT"

    return {
        "url":            raw_url,
        "resolved_url":   resolved if resolved != raw_url else None,
        "masked_url":     url_masked,
        "entropy":        round(domain_entropy, 4),
        "probability":    round(prob, 4),
        "prediction":     label,
        "threshold_used": THRESHOLD,
    }