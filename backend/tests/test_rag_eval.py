import pytest
import os
import json
from unittest.mock import patch, MagicMock

from eval.rag_eval_dataset import RAG_EVAL_DATASET
from eval.eval_rag import (
    evaluate_rag_retrieval,
    run_rag_evaluation,
    evaluate_single_query,
    is_title_match,
    compute_fact_coverage
)
from rag import keyword_fallback_retrieve, retrieve_relevant_chunks


class DummyChunk:
    def __init__(self, id, title, content, source_type, embedding=None):
        self.id = id
        self.title = title
        self.content = content
        self.source_type = source_type
        self.embedding = embedding


class TestRagEvaluationDataset:
    """Validate benchmark evaluation dataset schema, diversity, and completeness."""

    def test_dataset_size_and_categories(self):
        assert len(RAG_EVAL_DATASET) >= 15, "Evaluation dataset must contain at least 15 benchmark cases"

        categories = set(case["category"] for case in RAG_EVAL_DATASET)
        assert {"playbook", "mitre", "cve", "sigma_rule"}.issubset(categories), (
            "Dataset must cover playbook, mitre, cve, and sigma_rule categories"
        )
        for cat in ["playbook", "mitre", "cve", "sigma_rule"]:
            cat_cases = [c for c in RAG_EVAL_DATASET if c["category"] == cat]
            assert len(cat_cases) >= 2, f"Category '{cat}' must have at least 2 benchmark test cases"

    def test_dataset_case_structure(self):
        required_keys = {
            "id", "category", "query", "expected_chunk_titles",
            "expected_source_type", "expected_answer_facts"
        }
        seen_ids = set()
        for case in RAG_EVAL_DATASET:
            assert required_keys.issubset(case.keys()), f"Case {case.get('id')} missing required keys"
            assert case["id"] not in seen_ids, f"Duplicate case id: {case['id']}"
            seen_ids.add(case["id"])
            assert len(case["query"].strip()) > 10, f"Query for {case['id']} is too short or empty"
            assert len(case["expected_answer_facts"]) >= 1, f"Case {case['id']} must specify expected facts"
            assert case["expected_source_type"] in {"playbook", "mitre", "cve", "sigma_rule"}


class TestRagRetrievalMechanisms:
    """Validate keyword fallback and hybrid retrieval logic."""

    def test_keyword_fallback_direct(self):
        mock_chunks = [
            DummyChunk("c1", "Ransomware Response Playbook", "Isolate host, disable network, take snapshot.", "playbook"),
            DummyChunk("c2", "Phishing Triage", "Inspect email headers, extract IOCs.", "playbook"),
            DummyChunk("c3", "CVE-2021-44228 Log4Shell", "JNDI LDAP injection in Log4j library.", "cve")
        ]
        mock_db = MagicMock()
        mock_db.query.return_value.all.return_value = mock_chunks

        results = keyword_fallback_retrieve(mock_db, DummyChunk, "ransomware isolation host", top_k=2)
        assert len(results) > 0
        assert results[0].id == "c1"

    def test_keyword_fallback_empty_or_special_chars(self):
        mock_chunks = [
            DummyChunk("c1", "Test Title", "Some content.", "playbook")
        ]
        mock_db = MagicMock()
        mock_db.query.return_value.all.return_value = mock_chunks

        # Empty query should return chunks without crashing
        results = keyword_fallback_retrieve(mock_db, DummyChunk, "", top_k=2)
        assert len(results) == 1

        # Punctuation should be handled safely
        results2 = keyword_fallback_retrieve(mock_db, DummyChunk, "!@#$%^&*()", top_k=2)
        assert len(results2) == 1

    def test_retrieve_relevant_chunks_falls_back_when_embed_fails(self):
        """When embedding API fails or returns None, retrieve_relevant_chunks must fallback gracefully."""
        mock_chunks = [
            DummyChunk("c1", "Ransomware Response Playbook", "Contain lateral spread.", "playbook"),
            DummyChunk("c2", "DDoS Mitigation", "Rate limit ingress traffic.", "playbook")
        ]
        mock_db = MagicMock()
        mock_db.query.return_value.all.return_value = mock_chunks

        with patch("rag.embed_text", return_value=None):
            chunks = retrieve_relevant_chunks(mock_db, DummyChunk, "ransomware spread", top_k=1)
            assert len(chunks) == 1
            assert chunks[0].id == "c1"


class TestRagEvaluationEngine:
    """Validate metric calculations and benchmark targets."""

    def test_evaluate_single_query_scoring(self):
        case = {
            "id": "test_case_1",
            "category": "playbook",
            "query": "ransomware incident steps",
            "expected_chunk_titles": ["Ransomware Containment Playbook"],
            "expected_source_type": "playbook",
            "expected_answer_facts": ["isolate the host", "lateral movement"]
        }
        retrieved = [
            DummyChunk("c1", "Ransomware Containment Playbook", "Step 1: Isolate the host. Step 2: Stop lateral movement.", "playbook"),
            DummyChunk("c2", "Phishing Playbook", "Analyze headers.", "playbook")
        ]
        result = evaluate_single_query(case, retrieved, latency_ms=45.0, top_k=5)
        assert result["first_relevant_rank"] == 1
        assert result["rank_at_1"] is True
        assert result["mrr"] == 1.0
        assert result["recall_at_k"] == 1.0
        assert result["precision_at_k"] == 1.0
        assert result["citation_accurate"] is True
        assert result["fact_coverage"] == 1.0
        assert result["latency_ms"] == 45.0

    def test_rag_benchmark_target_thresholds(self):
        """Run the evaluation engine across all 18 cases and verify target SLAs pass."""
        results = run_rag_evaluation(top_k=5)
        metrics = results["overall_metrics"]

        assert metrics["mean_recall_at_k"] >= 0.70, f"Recall@5 ({metrics['mean_recall_at_k']}) below target 0.70"
        assert metrics["mean_precision_at_k"] >= 0.60, f"Precision@5 ({metrics['mean_precision_at_k']}) below target 0.60"
        assert metrics["mean_reciprocal_rank_mrr"] >= 0.65, f"MRR ({metrics['mean_reciprocal_rank_mrr']}) below target 0.65"
        assert metrics["source_citation_accuracy"] >= 0.80, f"Citation Acc ({metrics['source_citation_accuracy']}) below target 0.80"
        assert metrics["fact_coverage"] >= 0.75, f"Fact Coverage ({metrics['fact_coverage']}) below target 0.75"
        assert metrics["mean_latency_ms"] < 2000, f"Avg Latency ({metrics['mean_latency_ms']}) exceeds 2000ms"
        assert metrics["p95_latency_ms"] < 3000, f"P95 Latency ({metrics['p95_latency_ms']}) exceeds 3000ms"

    def test_report_artifact_exists(self):
        """Ensure 09-rag-evaluation.md and rag_evaluation_results.json exist on disk."""
        doc_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "09-rag-evaluation.md"))
        json_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "eval", "rag_evaluation_results.json"))
        assert os.path.exists(doc_path), "docs/09-rag-evaluation.md report does not exist"
        assert os.path.exists(json_path), "backend/eval/rag_evaluation_results.json does not exist"

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "overall_metrics" in data
            assert len(data.get("cases", [])) >= 15
