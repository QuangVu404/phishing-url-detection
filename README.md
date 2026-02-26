🛡️ Phishing URL Detection System

A Deep Learning-based phishing URL detection system using CNN, deployed with FastAPI and Docker.

This project builds an end-to-end pipeline from data preprocessing and model training to API deployment for real-time phishing URL prediction.

📌 Project Overview

Phishing attacks commonly use malicious URLs to trick users into revealing sensitive information.
This project aims to classify URLs as:

✅ Legitimate

🚨 Phishing

The system uses a Character-level Convolutional Neural Network (CNN) to learn URL patterns and detect suspicious structures.

🧠 Model Architecture

Character-level tokenization

Padding to fixed sequence length

Embedding Layer

1D Convolutional Layers

MaxPooling

Fully Connected Layers

Sigmoid output (Binary Classification)

📊 Dataset

Combined phishing and legitimate URL datasets

Duplicates removed

Data cleaned and normalized

Train / Validation / Test split

📈 Evaluation Metrics

The model is evaluated using:

Accuracy

Precision

Recall

F1-score

ROC-AUC

Confusion Matrix

Special focus is placed on Recall for the phishing class, since missing a phishing URL is more dangerous than a false alarm.

⚙️ Installation
1️⃣ Clone repository
git clone https://github.com/QuangVu404/phishing-url-detection.git
cd phishing-url-detection
2️⃣ Install dependencies
pip install -r requirements.txt
▶️ Run Locally

Start FastAPI server:

uvicorn app.main:app --reload

API will be available at:

http://127.0.0.1:8000

Swagger docs:

http://127.0.0.1:8000/docs
🐳 Run with Docker

Build image:

docker build -t phishing-detector .

Run container:

docker run -p 8000:8000 phishing-detector
🔍 API Usage
POST /predict

Request:

{
  "url": "http://example.com/login"
}

Response:

{
  "url": "http://example.com/login",
  "prediction": "phishing",
  "probability": 0.91
}
🧪 Training the Model

Open:

notebooks/training.ipynb

Steps included:

Data cleaning

Tokenization

Model training

Evaluation

Model saving

🏗 Technologies Used

Python

TensorFlow / Keras

Scikit-learn

FastAPI

Docker

📌 Future Improvements

Deploy to cloud (AWS / GCP / HuggingFace Spaces)

Add browser extension integration

Improve robustness against adversarial URLs

Add CI/CD pipeline
