from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import re
import httpx

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

EMAIL = "23f3001593@ds.study.iitm.ac.in"
OLLAMA_BASE = "http://localhost:11434"

# ── Ollama proxy ──────────────────────────────────────────────────────────────

@app.api_route("/api/{path:path}", methods=["GET", "POST", "DELETE", "HEAD", "OPTIONS"])
async def ollama_proxy(path: str, request: Request):
    url = f"{OLLAMA_BASE}/api/{path}"
    body = await request.body()

    async with httpx.AsyncClient(timeout=120.0) as client:
        proxied = await client.request(
            method=request.method,
            url=url,
            content=body,
            headers={"Content-Type": request.headers.get("Content-Type", "application/json")},
        )

    headers = {
        "X-Email": EMAIL,
        "Content-Type": request.headers.get("Content-Type", "application/json"),
        "Ngrok-Skip-Browser-Warning": "true",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "*",
        "Access-Control-Allow-Headers": "Authorization,Content-Type,User-Agent,Accept,Ngrok-skip-browser-warning",
    }

    return JSONResponse(
        content=proxied.json(),
        status_code=proxied.status_code,
        headers=headers,
    )

# ── Original sentiment endpoint ───────────────────────────────────────────────

class SentimentRequest(BaseModel):
    sentences: List[str]

class SentimentResult(BaseModel):
    sentence: str
    sentiment: str

class SentimentResponse(BaseModel):
    results: List[SentimentResult]

def clean_text(text: str) -> str:
    return re.sub(r"[^\w\s]", "", text.lower())

positive_words = {
    "love", "great", "awesome", "good", "happy", "amazing",
    "fantastic", "excellent", "nice", "wonderful", "best",
    "like", "enjoy", "positive", "brilliant", "super"
}
negative_words = {
    "sad", "bad", "terrible", "awful", "hate", "worst",
    "angry", "poor", "disappointing", "horrible", "ugly",
    "annoying", "dislike", "negative", "boring"
}

def get_sentiment(sentence: str) -> str:
    text = clean_text(sentence)
    pos_score = sum(1 for w in positive_words if w in text)
    neg_score = sum(1 for w in negative_words if w in text)
    if pos_score > neg_score:
        return "happy"
    elif neg_score > pos_score:
        return "sad"
    return "neutral"

@app.post("/sentiment", response_model=SentimentResponse)
def analyze_sentiment(request: SentimentRequest):
    results = [{"sentence": s, "sentiment": get_sentiment(s)} for s in request.sentences]
    return {"results": results}