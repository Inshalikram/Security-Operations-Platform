"""Real IPs pulled from the platform's own `indicators` history table —
verdicts are already known-good ground truth (no guessing)."""

EVAL_CASES = [
    {"id": "case_01", "ip": "8.213.132.151",   "expected_verdict": "malicious"},
    {"id": "case_02", "ip": "172.217.118.4",   "expected_verdict": "suspicious"},
    {"id": "case_03", "ip": "172.233.89.133",  "expected_verdict": "malicious"},
    {"id": "case_04", "ip": "164.132.172.225", "expected_verdict": "suspicious"},
    {"id": "case_05", "ip": "115.220.2.156",   "expected_verdict": "malicious"},
    {"id": "case_06", "ip": "163.192.121.134", "expected_verdict": "suspicious"},
    {"id": "case_07", "ip": "186.226.58.46",   "expected_verdict": "malicious"},
    {"id": "case_08", "ip": "218.98.6.202",    "expected_verdict": "malicious"},
    {"id": "case_09", "ip": "109.160.32.26",   "expected_verdict": "malicious"},
    {"id": "case_10", "ip": "139.162.189.5",   "expected_verdict": "malicious"},
    {"id": "case_11", "ip": "66.132.195.60",   "expected_verdict": "suspicious"},
    {"id": "case_12", "ip": "170.39.225.162",  "expected_verdict": "malicious"},
    {"id": "case_13", "ip": "223.111.161.82",  "expected_verdict": "malicious"},
    {"id": "case_14", "ip": "5.254.8.123",     "expected_verdict": "clean"},
    {"id": "case_15", "ip": "85.217.140.19",   "expected_verdict": "malicious"},
]