from pydantic import BaseModel

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    url: str
    probability: float
    prediction: str
    threshold_used: float