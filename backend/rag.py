import os
import math
import logging
import requests
from resilience import resilient_request

logger = logging.getLogger("rag")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
EMBED_MODEL = "gemini-embedding-001"


def embed_text(text: str):
    """Returns an embedding vector for the given text using Gemini's embedding model.
    Wrapped with retry and circuit breaker via resilient_request.
    Returns None on failure — callers must handle that (skip the chunk) rather than crash."""
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{EMBED_MODEL}:embedContent?key={GEMINI_API_KEY}"
        payload = {"content": {"parts": [{"text": text}]}}
        resp = resilient_request("gemini_embed", "POST", url, json=payload, timeout=20,
                                 max_attempts=2, recovery_timeout=30)
        return resp.json()["embedding"]["values"]
    except Exception as e:
        logger.warning(f"EMBED ERROR: {e}")
        return None


def cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0
    return dot / (norm_a * norm_b)


import re

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't",
    "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had", "hadn't",
    "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm",
    "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more",
    "most", "mustn't", "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or",
    "other", "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such", "than", "that", "that's",
    "the", "their", "theirs", "them", "themselves", "then", "there", "there's", "these", "they",
    "they'd", "they'll", "they're", "they've", "this", "those", "through", "to", "too", "under",
    "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't",
    "what", "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom",
    "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've",
    "your", "yours", "yourself", "yourselves"
}


def tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_\-\.]+", text.lower())
    return [t for t in tokens if len(t) > 1 and t not in STOPWORDS]


def keyword_fallback_retrieve(db_session, KnowledgeChunk, query: str, top_k: int = 5):
    """Fallback lexical matching when vector embedding is unavailable.
    Ranks chunks using term frequency and title keyword weighting."""
    query_tokens = tokenize(query)
    chunks = db_session.query(KnowledgeChunk).all()
    if not chunks:
        return []
    if not query_tokens:
        return chunks[:top_k]

    scored = []
    for chunk in chunks:
        title_text = (chunk.title or "").lower()
        content_text = (chunk.content or "").lower()
        score = 0.0

        for token in query_tokens:
            if token in title_text:
                score += 3.0
            if token in content_text:
                score += 1.0

        if score > 0:
            scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = [c for _, c in scored[:top_k]]
    if not results:
        results = chunks[:top_k]
    return results


def retrieve_relevant_chunks(db_session, KnowledgeChunk, query: str, top_k: int = 5):
    """Retrieves top-k relevant knowledge chunks. Attempts vector similarity first;
    falls back to keyword-based lexical ranking if embedding API is unavailable."""
    query_embedding = embed_text(query)
    if not query_embedding:
        return keyword_fallback_retrieve(db_session, KnowledgeChunk, query, top_k=top_k)

    chunks = db_session.query(KnowledgeChunk).all()
    scored = []
    for chunk in chunks:
        if not chunk.embedding:
            continue
        score = cosine_similarity(query_embedding, chunk.embedding)
        scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = [c for _, c in scored[:top_k]]
    if not results:
        return keyword_fallback_retrieve(db_session, KnowledgeChunk, query, top_k=top_k)
    return results