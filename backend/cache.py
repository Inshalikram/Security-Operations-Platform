import redis
import json
import os

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
    socket_connect_timeout=float(os.getenv("REDIS_CONNECT_TIMEOUT", 1.0)),
    socket_timeout=float(os.getenv("REDIS_TIMEOUT", 1.0)),
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
def acquire_lock(key: str, ttl_seconds: int = 300) -> bool:
    """Idempotency lock — SETNX pattern. Returns True agar lock mil gaya (pehli
    request), False agar koi aur already usi key pe kaam kar raha hai (duplicate).
    Redis down ho to fail-open: True return karo taake system block na ho —
    is case mein idempotency guarantee nahi milegi, lekin availability priority hai."""
    try:
        return bool(redis_client.set(key, "1", nx=True, ex=ttl_seconds))
    except Exception as e:
        print("REDIS LOCK ERROR (failing open):", e)
        return True