"""Pulls a fresh sample of real IPs from the indicators table each time eval
runs, instead of a hardcoded list — so evaluation always covers what the
system has actually seen recently, not a frozen snapshot."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # so `main` imports work

from main import SessionLocal, Indicator

OWN_SERVER_IP = "169.58.221.49"  # exclude — this is the VPS's own health-check IP, not a real case


def get_eval_cases(limit: int = 3):
    db = SessionLocal()
    records = (
        db.query(Indicator)
        .filter(Indicator.ip_address != OWN_SERVER_IP)
        .order_by(Indicator.checked_at.desc())
        .limit(limit * 4)  # oversample since we dedupe by IP below
        .all()
    )
    db.close()

    seen_ips = set()
    cases = []
    for r in records:
        if r.ip_address in seen_ips:
            continue
        seen_ips.add(r.ip_address)
        cases.append({
            "id": f"case_{len(cases) + 1:02d}",
            "ip": r.ip_address,
            "expected_verdict": r.verdict,
        })
        if len(cases) >= limit:
            break
    return cases


EVAL_CASES = get_eval_cases()