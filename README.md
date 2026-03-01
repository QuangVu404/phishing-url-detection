AI Phishing Shield: Phishing URL Detection System
This project is a Deep Learning-based phishing URL detection system using a 1D-CNN architecture. It is deployed as a FastAPI backend within a Docker container and integrated with a Chrome Extension for real-time user protection. The system, named "AI PHISHING SHIELD," features a backend API hosted on Hugging Face.

1. Project Overview
The project establishes a comprehensive end-to-end pipeline, covering data preprocessing, model training, and practical deployment. It utilizes a character-level 1D Convolutional Neural Network (1D-CNN) to identify malicious patterns in URL structures without the need for manual feature engineering.

2. Model Architecture
The model is designed to process URL data as sequences of characters through the following primary layers:

Character Tokenization: Converts the URL into a sequence of integers based on a character vocabulary.

Embedding Layer: Represents characters in a 64-dimensional low-dimensional vector space.

1D Convolutional Layers: Extracts local features (n-grams) from the URL character sequence.

Global MaxPooling: Retains the most significant features identified by the filters.

Fully Connected Layers: Classifies the URL based on the extracted features.

Sigmoid Output: Generates a probability score for binary classification (Legitimate vs. Phishing).

3. Data Pipeline
Data undergoes a rigorous three-step process to ensure high detection accuracy:

3.1. Cleaning
Converts all URLs to lowercase.

Removes protocols (e.g., http://, https://) and the www. prefix to focus on the core domain and path structure.

3.2. Sanitization
Uses Regular Expressions (Regex) to mask sensitive or highly variable components, allowing the model to focus on structural length rather than random noise:

IP Addresses: 192.168.1.1 → <IP_ADDRESS>.

Numeric IDs: /user/123456 → /user/<NUMERIC_ID_6>.

Hex/Hash Strings: ?sid=a1b2c3... → ?sid=<HASH_FORMAT_32>.

3.3. Vectorization
Max Length: Standardized to 500 characters.

Padding: Applies post-padding with zeros for sequences shorter than the maximum length.

4. Installation and Usage
Local Deployment
Install dependencies:

```bash
pip install -r requirements.txt
```
Start the server:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
API Documentation: Access the interactive Swagger UI at http://localhost:8000/docs.

Hugging Face Deployment
When deployed on Hugging Face Spaces, the API documentation (Swagger UI) is available at:
https://<username>-<space-name>.hf.space/docs

Docker Deployment

```bash
docker build -t phishing-detector .
docker run -p 8000:7860 phishing-detector
```
Chrome Extension Setup
Navigate to chrome://extensions/ in Google Chrome.

Enable Developer mode.

Click Load unpacked and select the extension source directory.

5. API Usage
Endpoint: POST /predict

Request Body:

```json
{
  "url": "http://example-malicious-site.com/login"
}
```

Response Body:

```json
{
  "url": "http://example-malicious-site.com/login",
  "prediction": "PHISHING",
  "probability": 0.4472,
  "status": "success"
}
```

6. Project Structure
```
├── app/                # FastAPI application (Routes, Schemas)
├── data/               # Data used in project
├── src/                # ML Logic (Preprocessing, Prediction, Loaders)
├── models/             # Model files (.keras), config (.json) and tokenizer (.pkl)
├── notebooks/          # Jupyter notebooks for training
├── tests/              # Unit testing scripts
└── Config Files/       # Configuration
```

7. Technologies Used
Language: Python 3.10+

AI Frameworks: TensorFlow 2.16+, Keras 3.0

Web Framework: FastAPI, Uvicorn

DevOps: Docker, Hugging Face Spaces

Frontend: JavaScript (Chrome Extension API)