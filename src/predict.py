from src.preprocessing import clean_url, sanitize_url
from src.model_loader import get_model
from src.tokenizer_loader import get_tokenizer
from src.config import MAX_LEN, THRESHOLD
from tensorflow.keras.preprocessing.sequence import pad_sequences

def predict_phishing(raw_url: str) -> dict:
    # 1. Lấy model & tokenizer
    model = get_model()
    tokenizer = get_tokenizer()
    
    # 2. Tiền xử lý
    url_clean = clean_url(raw_url)
    url_masked = sanitize_url(url_clean)
    
    # 3. Chuyển thành số
    seq = tokenizer.texts_to_sequences([url_masked])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
    
    # 4. Dự đoán
    prob = float(model.predict(padded, verbose=0).flatten()[0])
    is_phishing = prob > THRESHOLD
    
    return {
        "url": raw_url,
        "probability": round(prob, 4),
        "prediction": "PHISHING" if is_phishing else "LEGIT",
        "threshold_used": THRESHOLD
    }