import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .schemas import Classification, MessageRequest, Report, UrlRequest
from .url_analysis.analyzer import analyze_url as run_url_analysis

app = FastAPI(title="Vexora API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


def placeholder_report(submitted: str, missing_check: str) -> Report:
    """Returned until the real checks exist. Inconclusive is the only honest result."""
    return Report(
        input=submitted,
        classification=Classification.INCONCLUSIVE,
        indicators=[],
        confidence="No evidence collected",
        recommended_actions=["Do not rely on this result. Analysis is not implemented yet."],
        limitations=[f"{missing_check} is not implemented yet."],
        analysed_at=datetime.now(timezone.utc),
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze/url", response_model=Report)
def analyze_url(request: UrlRequest) -> Report:
    return run_url_analysis(request.url)


@app.post("/analyze/message", response_model=Report)
def analyze_message(request: MessageRequest) -> Report:
    # Person 2: treat the message as untrusted input, including for prompt injection.
    return placeholder_report(request.message, "Message analysis")
