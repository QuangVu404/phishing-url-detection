import pickle
import os

tokenizer_instance = None

def get_tokenizer():
    global tokenizer_instance
    if tokenizer_instance is None:
        path = os.getenv("TOKENIZER_PATH", "models\tokenizer_.pkl")
        print(f"Loading tokenizer from {path}...")
        with open(path, 'rb') as f:
            tokenizer_instance = pickle.load(f)
    return tokenizer_instance