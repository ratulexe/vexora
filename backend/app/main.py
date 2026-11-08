import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .ai import add_ai_analysis
from .correlation import correlate, message_features
from .message_analysis.analyzer import MESSAGE_ACTIONS
from .message_analysis.analyzer import analyze_message as run_message_analysis
from .rate_limit import LINK_ANALYSIS, MESSAGE_ANALYSIS
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
def analyze_url(body: UrlRequest, request: Request) -> Report:
    LINK_ANALYSIS.check(request, "Too many link checks from your connection.")
    return link_report(body.url, refresh=body.refresh)


@app.post("/analyze/message", response_model=Report)
def analyze_message(body: MessageRequest, request: Request) -> Report:
    MESSAGE_ANALYSIS.check(request, "Too many message checks from your connection.")
    report = run_message_analysis(body.message)
    # correlate() stores only a keyed hash of the message, never the text itself.
    report = correlate("message", body.message, message_features(body.message, report), report, MESSAGE_ACTIONS)
    return add_ai_analysis(report, message=body.message)
