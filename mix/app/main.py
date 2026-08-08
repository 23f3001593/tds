import os

import redis
from fastapi import FastAPI

app = FastAPI()

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


@app.post("/hit/{key}")
def hit(key: str):
    count = r.incr(f"counter:{key}")
    return {"key": key, "count": count}


@app.get("/count/{key}")
def count(key: str):
    value = r.get(f"counter:{key}")
    return {"key": key, "count": int(value) if value is not None else 0}


@app.get("/healthz")
def healthz():
    try:
        pong = r.ping()
        redis_status = "up" if pong else "down"
    except redis.exceptions.RedisError:
        redis_status = "down"
    return {"status": "ok", "redis": redis_status}