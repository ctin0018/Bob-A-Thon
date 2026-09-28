"""
demo.py -- Bob-A-Thon End-to-End Demo
IBM Bob x Developer Kaki Hackathon

Run this single file to see the full 3-tier pipeline in action:
  1. Starts the Prometheus metrics exporter on :8000
  2. Installs the PII masking filter on the root logger
  3. Fires sample log lines containing Malaysian NRICs and credit card numbers
  4. Prints the sanitized output to the console
  5. Prints the live Prometheus metric values
  6. Leaves the exporter running so you can open:
       http://localhost:8000/metrics   <- Prometheus scrape endpoint
       http://localhost:8000/healthz   <- Health check

Usage:
    python demo.py
"""

import logging
import time
import urllib.request

SEP = "-" * 65

# -- 1. Start the exporter FIRST (before importing sanitizer) ------------------
from exporter import start_exporter
start_exporter(port=8000, daemon=True)
print("[demo] Exporter started -> http://localhost:8000/metrics")

# -- 2. Install the global PII masking filter ----------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
)
from sanitizer import install_global_filter
install_global_filter(service="PaymentService")

logger = logging.getLogger("bob-a-thon.demo")

# -- 3. Fire sample log lines with PII ----------------------------------------
print("\n" + SEP)
print("  FIRING SAMPLE LOG LINES (watch PII get masked)")
print(SEP + "\n")

SAMPLES = [
    # NRIC variants (with and without dashes)
    "Customer lookup: nric=880101-14-5678 status=active",
    "Auth failed for ic_number=991231025432 attempt=3",
    # Credit card variants
    "Payment payload: card=4111111111111111 amount=RM450.00",
    "Refund processed card_number=5500005555555559 txn=TXN-0042",
    "Amex charge: 378282246310005 status=approved",
    # Multiple PII on one line
    "ERROR PaymentController.charge() nric=850615-10-1234 card=4012888888881881 FAILED",
    # Clean line -- should pass through unchanged
    "Health check OK: service=PaymentService latency=12ms",
]

for line in SAMPLES:
    logger.warning(line)
    time.sleep(0.05)

# -- 4. Show live Prometheus metric values ------------------------------------
time.sleep(0.3)  # let the exporter thread flush
print("\n" + SEP)
print("  LIVE PROMETHEUS METRICS  (http://localhost:8000/metrics)")
print(SEP + "\n")

with urllib.request.urlopen("http://localhost:8000/metrics", timeout=5) as resp:
    metrics_text = resp.read().decode()

# Print only the pii_* summary lines (skip histogram buckets for brevity)
for line in metrics_text.splitlines():
    if (
        line.startswith("pii_")
        and not line.startswith("pii_scan_duration_seconds_bucket")
        and not line.startswith("pii_transaction_response_seconds_bucket")
        and not line.startswith("#")
    ):
        print(line)

# -- 5. Show the 3-tier summary -----------------------------------------------
print("\n" + SEP)
print("  3-TIER BUSINESS OBSERVABILITY SUMMARY")
print(SEP)

def _sum_metric(name):
    total = 0.0
    for line in metrics_text.splitlines():
        if line.startswith(name) and not line.startswith("#"):
            try:
                total += float(line.split()[-1])
            except (ValueError, IndexError):
                pass
    return total

total     = _sum_metric("pii_log_interceptions_total")
rm_pen    = _sum_metric("pii_regulatory_risk_avoided_rm_total")
rm_cost   = _sum_metric("pii_engineering_cost_saved_rm_total")
mttd      = _sum_metric("pii_mttd_seconds")
mttr      = _sum_metric("pii_mttr_seconds")
hygiene   = _sum_metric("pii_compliance_hygiene_rate")

print()
print("  TIER 1 -- Executive & Financial Risk")
print(f"    Total PII Breaches Prevented : {total:.0f} tokens")
print(f"    Regulatory Penalty Avoided   : RM {rm_pen:,.0f}")
print(f"    Engineering Cost Saved       : RM {rm_cost:,.0f}")
print(f"    Compliance Hygiene Rate      : {hygiene * 100:.0f}%")

print()
print("  TIER 2 -- Operational Velocity")
print(f"    MTTD (Now)                   : {mttd * 1000:.1f} ms  (was 14 days)")
print(f"    MTTR (Now)                   : {mttr / 60:.0f} min  (was 127 min)")

print()
print("  TIER 3 -- Service Reliability")
print("    Masking overhead SLO target  : < 0.5 ms per log write")
print("    Transaction P90 SLO target   : < 2.0 s")
print("    Success Rate SLO target      : >= 99.9%")

print()
print(SEP)
print("  Exporter still running. Open http://localhost:8000/metrics")
print("  Import grafana/dashboard.json into Grafana to see the full")
print("  3-tier Business Observability Dashboard.")
print(SEP + "\n")

# Keep alive so you can browse the metrics endpoint
try:
    print("  Press Ctrl-C to stop.\n")
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[demo] Stopped.")
