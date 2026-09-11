import os
import logging
from elasticsearch import Elasticsearch
from resilience import resilient_call

logger = logging.getLogger("search")

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")

# ── Increased request timeout + automatic retry so one slow response doesn't silently fail
# the whole search. ──
es = Elasticsearch(
    ELASTICSEARCH_URL,
    request_timeout=15,
    max_retries=2,
    retry_on_timeout=True,
)

VALID_INDICES = ["suricata_alerts", "zeek_notices", "threat_indicators", "cases"]


def index_document(index: str, doc_id, body: dict):
    """Best-effort indexing with retry and circuit breaker — never let an ES failure
    break the caller (threat check / alert ingestion must keep working even if ES is down)."""
    try:
        resilient_call(
            "elasticsearch",
            es.index,
            index=index,
            id=doc_id,
            document=body,
            max_attempts=2,
            failure_threshold=3,
            recovery_timeout=30,
        )
    except Exception as e:
        logger.warning(f"ES INDEX ERROR for {index}/{doc_id}: {e}")


def search_all(query: str, size: int = 30):
    """Unified search across indices with circuit breaker and retry.
    Returns list of hits if successful, or None if Elasticsearch failed / circuit is open
    so that callers can gracefully fall back to PostgreSQL search."""
    try:
        result = resilient_call(
            "elasticsearch",
            es.search,
            index=",".join(VALID_INDICES),
            query={"multi_match": {"query": query, "fields": ["*"]}},
            size=size,
            ignore_unavailable=True,
            max_attempts=2,
            failure_threshold=3,
            recovery_timeout=30,
        )
        return [
            {"index": h["_index"], "score": h["_score"], **h["_source"]}
            for h in result["hits"]["hits"]
        ]
    except Exception as e:
        logger.warning(f"ES SEARCH ERROR: {e}")
        return None