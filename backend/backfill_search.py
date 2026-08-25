"""One-time backfill: indexes existing Postgres rows into Elasticsearch.
Run once after deploying search.py: python backfill_search.py
Safe to re-run — re-indexing with the same id just overwrites."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from main import SessionLocal, Indicator, SuricataAlert, ZeekNotice
from search import index_document

db = SessionLocal()

count = 0
for r in db.query(Indicator).all():
    index_document("threat_indicators", r.id, {
        "ip": r.ip_address, "verdict": r.verdict,
        "malicious_signals": r.malicious_signals, "country": r.country,
        "checked_at": r.checked_at.isoformat()
    })
    count += 1
print(f"Indexed {count} indicators")

count = 0
for r in db.query(SuricataAlert).all():
    index_document("suricata_alerts", r.id, {
        "src_ip": r.src_ip, "dest_ip": r.dest_ip,
        "signature": r.signature, "severity": r.severity,
        "timestamp": r.timestamp.isoformat()
    })
    count += 1
print(f"Indexed {count} suricata alerts")

count = 0
for r in db.query(ZeekNotice).all():
    index_document("zeek_notices", r.id, {
        "note_type": r.note_type, "message": r.message,
        "src_ip": r.src_ip, "dest_ip": r.dest_ip,
        "timestamp": r.timestamp.isoformat()
    })
    count += 1
print(f"Indexed {count} zeek notices")

db.close()
print("Backfill complete.")