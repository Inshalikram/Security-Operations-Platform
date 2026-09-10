import time
import logging
import requests

logger = logging.getLogger("resilience")


class CircuitBreaker:
    def __init__(self, name, failure_threshold=5, recovery_timeout=60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.state = "closed"
        self.opened_at = None

    def record_success(self):
        self.failures = 0
        self.state = "closed"

    def record_failure(self):
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "open"
            self.opened_at = time.time()
            logger.warning(f"Circuit OPEN for {self.name} after {self.failures} failures")

    def allow_request(self):
        if self.state == "open":
            if time.time() - self.opened_at > self.recovery_timeout:
                self.state = "half_open"
                return True
            return False
        return True


_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(name, **kwargs) -> CircuitBreaker:
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name, **kwargs)
    return _breakers[name]


def resilient_request(service_name, method, url, max_attempts=3, timeout=10,
                       failure_threshold=5, recovery_timeout=60, **kwargs):
    breaker = get_breaker(service_name, failure_threshold=failure_threshold,
                           recovery_timeout=recovery_timeout)
    if not breaker.allow_request():
        raise RuntimeError(f"{service_name}_circuit_open: too many recent failures, skipping call")

    # requests.request() ki jagah requests.get/requests.post use karo — tests
    # unittest.mock.patch("requests.get") / patch("main.requests.get") karte hain,
    # aur wo sirf requests.get ko intercept karta hai, requests.request() ko nahi.
    request_fn = getattr(requests, method.lower())

    attempt = 0
    last_exc = None
    while attempt < max_attempts:
        attempt += 1
        try:
            resp = request_fn(url, timeout=timeout, **kwargs)
            if resp.status_code >= 500:
                raise requests.exceptions.HTTPError(f"{service_name} returned {resp.status_code}", response=resp)
            breaker.record_success()
            return resp
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            last_exc = e
            if attempt >= max_attempts:
                breaker.record_failure()
                logger.error(f"{service_name} failed after {attempt} attempts: {e}")
                raise
            delay = min(0.5 * (2 ** (attempt - 1)), 8.0)
            logger.warning(f"{service_name} attempt {attempt} failed ({e}), retrying in {delay}s")
            time.sleep(delay)
    raise last_exc

def build_dlq_entry(service: str, payload: dict, error: str) -> dict:
    return {
        "service": service,
        "payload": payload,
        "error": error,
        "failed_at": time.time(),
    }