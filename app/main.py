from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router

from src.predict import init_resources

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_resources()
    yield

app = FastAPI(
    title="AI Phishing Shield API", 
    version="2.0.0",
    lifespan=lifespan 
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)