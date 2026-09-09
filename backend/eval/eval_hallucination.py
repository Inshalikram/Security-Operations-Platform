"""Runs /ai/rag-explain/{ip} for each IP in EVAL_CASES, then uses a SEPARATE
AI call ("judge") to check whether the generated explanation only makes claims
traceable to the actual threat data + retrieved knowledge chunks — i.e. checks
for hallucination. Run: python eval/eval_hallucination.py"""

import json
import time
from datetime import datetime
from eval_dataset import EVAL_CASES

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # so `main` imports work

from main import unified_threat_check, call_ai, SessionLocal, KnowledgeChunk, get_similar_past_incidents
from rag import retrieve_relevant_chunks

DELAY_BETWEEN_CASES_SECONDS = 8   # avoid rate limiting
RETRY_DELAY_SECONDS = 15
EVAL_PROVIDER = "ollama"   # use local Ollama — no quota/rate limits


def judge_hallucination(explanation: str, threat_data: dict, past_incidents: list, retrieved_chunks: list, retries: int = 1) -> dict:
    """A second, independent AI call fact-checks the explanation against ONLY
    the data that was actually available to it — flags any claim that isn't
    traceable back to that source data. Retries once on rate-limit/timeout/503."""
    context_text = "\n".join(
        f"- [{c.source_type}] {c.title}: {c.content[:250]}" for c in retrieved_chunks
    ) or "(no knowledge base chunks retrieved)"

    judge_prompt = f"""You are a strict fact-checker reviewing an AI-generated security explanation.

Below is (1) the ONLY source data the AI had access to, and (2) the explanation it wrote.
Identify any factual claim in the explanation that is NOT supported by the source data
(i.e. invented, exaggerated, or assumed beyond what the evidence shows).

SOURCE DATA — current threat intel finding:
{json.dumps(threat_data, indent=2)[:1200]}

SOURCE DATA — this IP's past history:
{json.dumps(past_incidents, indent=2)[:600]}

SOURCE DATA — knowledge base chunks retrieved:
{context_text}

EXPLANATION TO CHECK:
{explanation}

Respond ONLY with this exact JSON, nothing else, no markdown fences:
{{"hallucinated": true/false, "hallucinated_claims": ["claim 1", "claim 2"], "groundedness_score": <0-100>, "notes": "<one sentence>"}}"""

    try:
        raw = call_ai(judge_prompt, provider=EVAL_PROVIDER, feature="hallucination_judge")
        cleaned = raw.strip().strip("```json").strip("```").strip()
        return json.loads(cleaned)
    except Exception as e:
        err = str(e)
        if retries > 0 and ("429" in err or "503" in err or "timed out" in err or "UNAVAILABLE" in err):
            time.sleep(RETRY_DELAY_SECONDS)
            return judge_hallucination(explanation, threat_data, past_incidents, retrieved_chunks, retries - 1)
        return {"hallucinated": None, "hallucinated_claims": [], "groundedness_score": None, "notes": f"judge_error: {err}"}


def run_case(case: dict, retries: int = 1) -> dict:
    result = {"case_id": case["id"], "ip": case["ip"]}
    start = time.monotonic()
    try:
        threat_data = unified_threat_check(case["ip"])
        past_incidents = get_similar_past_incidents(case["ip"])

        db = SessionLocal()
        query_text = f"IP {case['ip']} verdict {threat_data['overall_verdict']} signals {threat_data['malicious_signals']}"
        retrieved_chunks = retrieve_relevant_chunks(db, KnowledgeChunk, query_text, top_k=5)
        db.close()

        history_text = "No previous history found." if not past_incidents else "\n".join(
            f"- {p['checked_at']}: verdict={p['verdict']}, signals={p['malicious_signals']}" for p in past_incidents
        )
        knowledge_text = "No relevant knowledge base entries found." if not retrieved_chunks else "\n".join(
            f"- [{c.source_type}] {c.title}: {c.content[:200]}" for c in retrieved_chunks
        )

        prompt = f"""You are a SOC analyst assistant with access to historical data and an internal knowledge base.

Current finding:
IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}

Past history for this IP:
{history_text}

Relevant knowledge base entries:
{knowledge_text}

Explain whether this is a recurring threat pattern, which MITRE techniques or playbooks are relevant, and what that means for prioritization.

IMPORTANT — grounding rules:
- Only state facts that are explicitly present in the data above. Do not infer hosting providers, ASN ownership, or infrastructure details unless stated.
- Do not change or override any severity/status value given above — report it as-is.
- If a playbook is referenced, use its exact step count and content — do not paraphrase or drop steps.
- Count each history entry and the current finding as distinct events only if their timestamps are meaningfully different (not the same second)."""

        explanation = call_ai(prompt, provider=EVAL_PROVIDER, feature="rag_eval_explain")
        result["verdict"] = threat_data["overall_verdict"]
        result["verdict_match"] = threat_data["overall_verdict"] == case["expected_verdict"]
        result["knowledge_sources_used"] = [{"type": c.source_type, "title": c.title} for c in retrieved_chunks]
        result["judge"] = judge_hallucination(explanation, threat_data, past_incidents, retrieved_chunks)
        result["explanation_preview"] = explanation[:300]
        result["failed"] = False
    except Exception as e:
        err = str(e)
        if retries > 0 and ("429" in err or "503" in err or "timed out" in err or "UNAVAILABLE" in err):
            time.sleep(RETRY_DELAY_SECONDS)
            return run_case(case, retries - 1)
        result["failed"] = True
        result["error"] = err

    result["latency_seconds"] = round(time.monotonic() - start, 2)
    return result


def run_suite():
    results = []
    for i, case in enumerate(EVAL_CASES):
        results.append(run_case(case))
        if i < len(EVAL_CASES) - 1:
            time.sleep(DELAY_BETWEEN_CASES_SECONDS)

    succeeded = [r for r in results if not r["failed"]]
    judged = [r for r in succeeded if r["judge"].get("hallucinated") is not None]
    hallucinated_cases = [r for r in judged if r["judge"]["hallucinated"] is True]

    summary = {
        "run_at": datetime.utcnow().isoformat(),
        "provider": EVAL_PROVIDER,
        "total_cases": len(results),
        "failed_cases": len(results) - len(succeeded),
        "judged_cases": len(judged),
        "cases_with_hallucination": len(hallucinated_cases),
        "hallucination_rate": round(len(hallucinated_cases) / len(judged), 3) if judged else None,
        "avg_groundedness_score": round(
            sum(r["judge"]["groundedness_score"] for r in judged) / len(judged), 1
        ) if judged else None,
        "verdict_accuracy": round(sum(1 for r in succeeded if r["verdict_match"]) / len(succeeded), 3) if succeeded else None,
        "avg_latency_seconds": round(sum(r["latency_seconds"] for r in results) / len(results), 2),
        "hallucinated_case_ids": [r["case_id"] for r in hallucinated_cases],
    }

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(json.dumps(summary, indent=2))

    if hallucinated_cases:
        print("\n" + "=" * 60)
        print("FLAGGED HALLUCINATIONS — DETAIL")
        print("=" * 60)
        for r in hallucinated_cases:
            print(f"\n[{r['case_id']}] IP: {r['ip']}")
            print(f"  Claims flagged: {r['judge']['hallucinated_claims']}")
            print(f"  Notes: {r['judge']['notes']}")

    fname = f"eval_hallucination_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump({"summary": summary, "cases": results}, f, indent=2)
    print(f"\nFull results saved to {fname}")

    return summary, results


if __name__ == "__main__":
    run_suite()