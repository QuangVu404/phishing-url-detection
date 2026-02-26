import tensorflow as tf
import os

model_instance = None

def get_model():
    global model_instance
    if model_instance is None:
        path = os.getenv("MODEL_PATH", "models/resnet1d_se_20260224_165928.keras")
        print(f"Loading model from {path}...")
        model_instance = tf.keras.models.load_model(path, compile=False)
    return model_instance