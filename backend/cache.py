import redis
import json
import os

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
)


def get_cached(key: str):
    """Returns cached dict if present, else None. Never raises — cache errors
    should never break the actual threat-check flow."""
    try:
        val = redis_client.get(key)
        return json.loads(val) if val else None
    except Exception as e:
        print("REDIS GET ERROR:", e)
        return None


def set_cached(key: str, value: dict, ttl_seconds: int = 3600):
    try:
        redis_client.setex(key, ttl_seconds, json.dumps(value))
    except Exception as e:
        print("REDIS SET ERROR:", e)