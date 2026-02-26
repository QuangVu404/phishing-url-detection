install:
	pip install -r requirements.txt

run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/

docker-build:
	docker build -t phishing-shield-api .

docker-run:
	docker run -p 8000:8000 phishing-shield-api