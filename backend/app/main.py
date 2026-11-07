import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .ai import add_ai_analysis
from .message_analysis.analyzer import analyze_message as run_message_analysis
from .registry.api import router as registry_router
from .report_cache import link_report
from .schemas import MessageRequest, Report, UrlRequest

app = FastAPI(title="Vexora API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(registry_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze/url", response_model=Report)
def analyze_url(request: UrlRequest) -> Report:
    return link_report(request.url, refresh=request.refresh)


@app.post("/analyze/message", response_model=Report)
def analyze_message(request: MessageRequest) -> Report:
    return add_ai_analysis(run_message_analysis(request.message), message=request.message)
