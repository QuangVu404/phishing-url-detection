import pandas as pd
import os
from src.preprocessing import clean_url, sanitize_url, unshorten_url
from src.model_loader import get_model
from src.tokenizer_loader import get_tokenizer
from src.caculate_entropy import calculate_entropy
from src.config import MAX_LEN, THRESHOLD
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Get model & tokenizer
model = get_model()
tokenizer = get_tokenizer()

Tranco_FILE_PATH = 'data/top-1m-Tranco-list.csv'
df_tranco = pd.read_csv(Tranco_FILE_PATH, header=None)
GLOBAL_TRUSTED_DOMAINS = set(df_tranco[1].astype(str).str.lower().tolist())

def predict_phishing(raw_url):
    """
    Predict whether a URL is Phishing or Legit, integrating Masking, Entropy, and Whitelist.
    """
    url = unshorten_url(str(raw_url))

    entropy_score = calculate_entropy(str(url))
    
    # Preprocessing
    url_clean = clean_url(url)
    url_clean = url_clean.rstrip('/')
    
    if url_clean in GLOBAL_TRUSTED_DOMAINS:
        return {
            "url": raw_url,
            "final_url": url if url != raw_url else None,
            "probability": 0.00,
            "prediction": "LEGIT",
            "threshold_used": 0.5
        }

    domain = url_clean.split('/')[0]
    main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
    
    url_masked = sanitize_url(url_clean)
    
    seq = tokenizer.texts_to_sequences([url_masked])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
    
    prob = float(model.predict(padded, verbose=0).flatten()[0])
    threshold = THRESHOLD
    
    # Reduce risk by 40% if it's a trusted domain and add risk if the code is highly chaotic
    if main_domain in GLOBAL_TRUSTED_DOMAINS or domain in GLOBAL_TRUSTED_DOMAINS:
        prob = prob * 0.6
    if entropy_score > 5.0:
        prob = min(1.0, prob + 0.1)
    
    label = 'PHISHING' if prob > threshold else 'LEGIT'
    
    return {
        "url": raw_url,
        "final_url": url if url != raw_url else None,
        "probability": round(prob, 4),
        "prediction": label,
        "threshold_used": THRESHOLD
    }