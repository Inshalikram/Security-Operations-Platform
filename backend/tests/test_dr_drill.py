import pytest
import os
import json
import sys
from datetime import datetime, timezone

# Add scripts directory to path to import dr_drill
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from dr_drill import (
    run_dr_drill,
    canonical_row,
    compute_table_checksum,
    seed_baseline_data_if_needed,
    get_minio_store,
    get_keycloak_realm_config,
    TABLE_MODELS,
    MockMinIOStorage
)
from main import SessionLocal, Asset, Organization


class TestDisasterRecoveryComponents:
    """Tests for disaster recovery modular components (hashing, MinIO, Keycloak)."""

    def test_canonical_row_determinism(self):
        """Canonical row serializer must produce deterministic output regardless of dictionary key order or formatting."""
        asset = Asset(
            id=999,
            tenant_id="tenant-test",
            name="firewall-core",
            ip_address="10.10.10.1",
            asset_type="firewall",
            owner="SecOps",
            criticality="critical",
            status="active",
            created_at=datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)
        )
        row1 = canonical_row(asset, Asset)
        row2 = canonical_row(asset, Asset)
        assert row1 == row2
        assert "firewall-core" in row1
        assert "2026-09-11T12:00:00+00:00" in row1

    def test_mock_minio_lifecycle(self, tmp_path):
        """Validates object store put, list, and purge operations."""
        store = MockMinIOStorage(storage_dir=str(tmp_path / "minio_test"))
        store.put_object("reports", "test_report.pdf", b"PDF_SAMPLE_DATA")
        store.put_object("evidence", "pcap.bin", b"PCAP_SAMPLE_DATA")

        objs = store.list_objects()
        assert len(objs) == 2
        assert "reports/test_report.pdf" in objs
        assert "evidence/pcap.bin" in objs
        assert objs["reports/test_report.pdf"]["size"] == len(b"PDF_SAMPLE_DATA")

        store.purge_all()
        assert len(store.list_objects()) == 0

    def test_keycloak_realm_export_structure(self):
        """Validates Keycloak realm config schema, roles, and clients."""
        realm = get_keycloak_realm_config()
        assert realm["realm"] == "soc-platform"
        assert realm["enabled"] is True
        
        role_names = [r["name"] for r in realm["roles"]["realm"]]
        assert {"admin", "analyst", "viewer", "soc_lead"}.issubset(set(role_names))

        client_ids = [c["clientId"] for c in realm["clients"]]
        assert {"soc-frontend", "soc-backend", "thehive", "grafana"}.issubset(set(client_ids))


class TestDisasterRecoveryDrillExecution:
    """Full drill execution, destruction simulation, restoration, and SLA verification."""

    def test_full_dr_drill_and_integrity(self):
        """Executes complete DR drill and verifies 100% data integrity and zero record loss."""
        db = SessionLocal()
        results = run_dr_drill(custom_db=db, verbose=False)

        # 1. Overall verdict
        assert results["drill_metadata"]["overall_verdict"] == "SUCCESS"

        # 2. Integrity verifications
        integ = results["integrity_verification"]
        assert integ["overall_integrity_passed"] is True
        assert integ["database_tables_verified"] is True
        assert integ["minio_objects_verified"] is True
        assert integ["keycloak_realm_verified"] is True

        # 3. Table delta check
        assert results["measured_metrics"]["total_data_loss_records"] == 0
        for tbl in integ["table_details"]:
            assert tbl["row_delta"] == 0, f"Table {tbl['table']} had row delta: {tbl['row_delta']}"
            assert tbl["checksum_match"] is True, f"Table {tbl['table']} checksum mismatch"
            assert tbl["status"] == "PASS"

    def test_rto_and_rpo_sla_compliance(self):
        """Verifies measured RTO and RPO are strictly within SLA targets."""
        db = SessionLocal()
        results = run_dr_drill(custom_db=db, verbose=False)
        m = results["measured_metrics"]

        # RTO must be <= 2 hours (7200 seconds)
        assert m["measured_rto_seconds"] <= m["rto_sla_target_seconds"]
        assert m["rto_status"] == "PASSED"
        # In this drill with local restoration, RTO should be exceptionally fast (< 30s)
        assert m["measured_rto_seconds"] < 30.0

        # RPO must be <= 24 hours (86400 seconds)
        assert m["measured_rpo_seconds"] <= m["rpo_sla_target_seconds"]
        assert m["rpo_status"] == "PASSED"

    def test_dr_drill_reports_generated(self):
        """Ensures dr-drill-results.md exists in root and docs/ and contains required tables."""
        root_report = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dr-drill-results.md"))
        docs_report = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "dr-drill-results.md"))

        assert os.path.exists(root_report), "Root dr-drill-results.md does not exist"
        assert os.path.exists(docs_report), "docs/dr-drill-results.md does not exist"

        with open(root_report, "r", encoding="utf-8") as f:
            content = f.read()

        assert "# Disaster Recovery Drill Report (`dr-drill-results.md`)" in content
        assert "Recovery Time Objective (RTO)" in content
        assert "Recovery Point Objective (RPO)" in content
        assert "Core Service Recovery Matrix" in content
        assert "Overall Drill Verdict:" in content
        assert "SUCCESS" in content
