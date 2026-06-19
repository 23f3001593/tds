# Q11
# from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from typing import List
# import re
# app = FastAPI()
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
# class SentimentRequest(BaseModel):
#     sentences: List[str]
# class SentimentResult(BaseModel):
#     sentence: str
#     sentiment: str
# class SentimentResponse(BaseModel):
#     results: List[SentimentResult]
# def clean_text(text: str) -> str:
#     return re.sub(r"[^\w\s]", "", text.lower())
# positive_words = {
#     "love", "great", "awesome", "good", "happy", "amazing",
#     "fantastic", "excellent", "nice", "wonderful", "best",
#     "like", "enjoy", "positive", "brilliant", "super"
# }
# negative_words = {
#     "sad", "bad", "terrible", "awful", "hate", "worst",
#     "angry", "poor", "disappointing", "horrible", "ugly",
#     "annoying", "dislike", "negative", "boring"
# }
# def get_sentiment(sentence: str) -> str:
#     text = clean_text(sentence)
#     pos_score = 0
#     neg_score = 0
#     for word in positive_words:
#         if word in text:
#             pos_score += 1
#     for word in negative_words:
#         if word in text:
#             neg_score += 1
#     if pos_score > neg_score:
#         return "happy"
#     elif neg_score > pos_score:
#         return "sad"
#     else:
#         return "neutral"
# @app.post("/sentiment", response_model=SentimentResponse)
# def analyze_sentiment(request: SentimentRequest):
#     results = []
#     for sentence in request.sentences:
#         sentiment = get_sentiment(sentence)
#         results.append({
#             "sentence": sentence,
#             "sentiment": sentiment
#         })
#     return {"results": results}