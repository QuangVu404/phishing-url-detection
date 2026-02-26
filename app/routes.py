from fastapi import APIRouter
from app.schemas import URLRequest, PredictionResponse
from src.predict import predict_phishing

router = APIRouter()

@router.post("/predict", response_model=PredictionResponse)
async def predict_endpoint(request: URLRequest):
    result = predict_phishing(request.url)
    return result

@router.get("/health")
async def health_check():
    return {"status": "System Online", "model": "Loaded"}