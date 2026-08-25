import os
import math
import requests

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
EMBED_MODEL = "gemini-embedding-001"


def embed_text(text: str):
    """Returns an embedding vector for the given text using Gemini's embedding model.
    Returns None on failure — callers must handle that (skip the chunk) rather than crash."""
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{EMBED_MODEL}:embedContent?key={GEMINI_API_KEY}"
        payload = {"content": {"parts": [{"text": text}]}}
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()["embedding"]["values"]
    except Exception as e:
        print("EMBED ERROR:", e)
        return None


def cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0
    return dot / (norm_a * norm_b)


def retrieve_relevant_chunks(db_session, KnowledgeChunk, query: str, top_k: int = 5):
    """Embeds the query, scores it against every stored chunk's embedding in Python,
    and returns the top_k most similar chunks. Fine at hundreds-of-chunks scale;
    would need pgvector or a real vector DB if this grows into the tens of thousands."""
    query_embedding = embed_text(query)
    if not query_embedding:
        return []

    chunks = db_session.query(KnowledgeChunk).all()
    scored = []
    for chunk in chunks:
        if not chunk.embedding:
            continue
        score = cosine_similarity(query_embedding, chunk.embedding)
        scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:top_k]]