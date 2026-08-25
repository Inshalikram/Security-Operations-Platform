import os
from elasticsearch import Elasticsearch

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
es = Elasticsearch(ELASTICSEARCH_URL)

VALID_INDICES = ["suricata_alerts", "zeek_notices", "threat_indicators", "cases"]


def index_document(index: str, doc_id, body: dict):
    """Best-effort indexing — never let an ES failure break the caller
    (threat check / alert ingestion must keep working even if ES is down)."""
    try:
        es.index(index=index, id=doc_id, document=body)
    except Exception as e:
        print("ES INDEX ERROR:", e)


def search_all(query: str, size: int = 30):
    try:
        result = es.search(
            index=",".join(VALID_INDICES),
            query={"multi_match": {"query": query, "fields": ["*"]}},
            size=size,
            ignore_unavailable=True,  # skip indices that don't exist yet, don't error out
        )
        return [
            {"index": h["_index"], "score": h["_score"], **h["_source"]}
            for h in result["hits"]["hits"]
        ]
    except Exception as e:
        print("ES SEARCH ERROR:", e)
        return []