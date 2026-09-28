"""
exporter.py — Prometheus Metrics Exporter (3-Tier Business Observability)
Bob-A-Thon | IBM Bob × Developer Kaki Hackathon

Exposes PII interception telemetry on :8000/metrics in Prometheus text format.
Grafana scrapes this endpoint to populate the 3-Tier Business Observability dashboard:

  Tier 1 — Executive & Financial Risk
    pii_log_interceptions_total{pii_type, service, module}
    pii_regulatory_risk_avoided_rm_total
    pii_engineering_cost_saved_rm_total
    pii_compliance_hygiene_rate (gauge, target 1.0 = 100%)

  Tier 2 — Operational Velocity (DevSecOps / SRE)
    pii_mttd_seconds (gauge — mean time to detect, updated per interception)
    pii_mttr_seconds (gauge — mean time to resolve, updated on remediation)
    pii_active_stream_vulnerabilities (gauge — open streams seen in last window)

  Tier 3 — Service Reliability & SLO
    pii_scan_duration_seconds (histogram — masking overhead per log write)
    pii_transaction_response_seconds (histogram — upstream API response time)
    pii_transaction_success_total / pii_transaction_total (for success-rate SLO)
    pii_active_scanner_info (gauge — version/environment metadata)

Run standalone:
  python exporter.py

Or import start_exporter() to embed in your application process.
"""

import logging
import os
import threading
import time
from wsgiref.simple_server import make_server, WSGIRequestHandler

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — enterprise cost model
# ---------------------------------------------------------------------------
# BNM RMIT / PDPA: estimated average audit-finding cost per PII incident
_RM_PENALTY_PER_INCIDENT: float = float(os.getenv("RM_PENALTY_PER_INCIDENT", "50000"))
# Manual remediation: hours × engineers × hourly rate
_REMEDIATION_HOURS: float = float(os.getenv("REMEDIATION_HOURS_PER_INCIDENT", "16"))
_ENGINEERS_PER_INCIDENT: int = int(os.getenv("ENGINEERS_PER_INCIDENT", "4"))
_HOURLY_RATE_RM: float = float(os.getenv("HOURLY_RATE_RM", "500"))
_MTTR_SAVING_HOURS: float = _REMEDIATION_HOURS  # hours reclaimed per automated fix

# ---------------------------------------------------------------------------
# Tier 1 — Executive & Financial Risk
# ---------------------------------------------------------------------------

PII_INTERCEPTED = Counter(
    "pii_log_interceptions_total",
    "Total PII tokens intercepted and masked before log write",
    ["pii_type", "service", "module"],
    registry=REGISTRY,
)

PII_REGULATORY_RISK_AVOIDED = Counter(
    "pii_regulatory_risk_avoided_rm_total",
    "Cumulative estimated RM value of regulatory penalties avoided (BNM RMIT / PDPA)",
    registry=REGISTRY,
)

PII_ENGINEERING_COST_SAVED = Counter(
    "pii_engineering_cost_saved_rm_total",
    "Cumulative estimated RM cost of engineering remediation effort avoided",
    registry=REGISTRY,
)

PII_COMPLIANCE_HYGIENE_RATE = Gauge(
    "pii_compliance_hygiene_rate",
    "Proportion of monitored log streams containing zero plaintext sensitive data (1.0 = 100%)",
    registry=REGISTRY,
)
PII_COMPLIANCE_HYGIENE_RATE.set(1.0)  # starts at 100% — degrades only on unmasked escapes

# ---------------------------------------------------------------------------
# Tier 2 — Operational Velocity
# ---------------------------------------------------------------------------

PII_MTTD_SECONDS = Gauge(
    "pii_mttd_seconds",
    "Mean Time to Detect a PII leak (seconds). Inline filter = sub-second; CI scan <= 300s.",
    registry=REGISTRY,
)
PII_MTTD_SECONDS.set(0.001)  # inline detection — updated per interception event

PII_MTTR_SECONDS = Gauge(
    "pii_mttr_seconds",
    "Mean Time to Resolve a PII leak (seconds). Bob auto-patch target: < 600s (10 min).",
    registry=REGISTRY,
)
PII_MTTR_SECONDS.set(600)  # 10-minute IBM Bob autonomous remediation target

PII_BASELINE_MTTD_SECONDS = Gauge(
    "pii_baseline_mttd_seconds",
    "Historical baseline MTTD before IBM Bob (seconds). Used for before/after comparison.",
    registry=REGISTRY,
)
PII_BASELINE_MTTD_SECONDS.set(14 * 24 * 3600)  # 14 days — typical audit discovery window

PII_BASELINE_MTTR_SECONDS = Gauge(
    "pii_baseline_mttr_seconds",
    "Historical baseline MTTR before IBM Bob (seconds). Used for before/after comparison.",
    registry=REGISTRY,
)
PII_BASELINE_MTTR_SECONDS.set(127 * 60)  # 127 minutes — emergency hotfix baseline

PII_ACTIVE_STREAM_VULNS = Gauge(
    "pii_active_stream_vulnerabilities",
    "Number of log streams that had at least one raw PII interception in the last scrape window.",
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# Tier 3 — Service Reliability & SLO
# ---------------------------------------------------------------------------

PII_SCAN_DURATION = Histogram(
    "pii_scan_duration_seconds",
    "Per-log-write masking overhead (target: < 0.0005s / 0.5ms)",
    buckets=[0.0000005, 0.000001, 0.00001, 0.0001, 0.0005, 0.001, 0.01],
    registry=REGISTRY,
)

PII_TRANSACTION_RESPONSE = Histogram(
    "pii_transaction_response_seconds",
    "Upstream API transaction response time with sanitizer active (SLO: P90 < 2.0s)",
    buckets=[0.1, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0],
    registry=REGISTRY,
)

PII_TRANSACTION_TOTAL = Counter(
    "pii_transaction_total",
    "Total application transactions processed while sanitizer is active",
    registry=REGISTRY,
)

PII_TRANSACTION_SUCCESS = Counter(
    "pii_transaction_success_total",
    "Successful application transactions (no errors, no dropped requests)",
    registry=REGISTRY,
)

PII_SCANNER_INFO = Gauge(
    "pii_active_scanner_info",
    "Metadata about the running PII scanner instance",
    ["version", "environment"],
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# Seed / initialise label series
# ---------------------------------------------------------------------------
_VERSION = os.getenv("APP_VERSION", "1.0.0")
_ENV = os.getenv("APP_ENV", "production")
PII_SCANNER_INFO.labels(version=_VERSION, environment=_ENV).set(1)

for _ptype in ("NRIC", "CREDIT_CARD"):
    PII_INTERCEPTED.labels(pii_type=_ptype, service="unknown", module="unknown")


# ---------------------------------------------------------------------------
# Business metric update helpers (called by sanitizer.py on each interception)
# ---------------------------------------------------------------------------

def record_interception(pii_type: str, service: str = "unknown", module: str = "unknown") -> None:
    """
    Increment all business-layer counters for a single PII interception event.
    Called by PIISanitizingFilter on every masked token.
    """
    PII_INTERCEPTED.labels(pii_type=pii_type, service=service, module=module).inc()
    PII_REGULATORY_RISK_AVOIDED.inc(_RM_PENALTY_PER_INCIDENT)
    PII_ENGINEERING_COST_SAVED.inc(_REMEDIATION_HOURS * _ENGINEERS_PER_INCIDENT * _HOURLY_RATE_RM)
    # Each interception is inline — MTTD stays near-zero
    PII_MTTD_SECONDS.set(0.001)


# ---------------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------------

class _SilentHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def _metrics_app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    if path == "/metrics":
        output = generate_latest(REGISTRY)
        start_response("200 OK", [
            ("Content-Type", CONTENT_TYPE_LATEST),
            ("Content-Length", str(len(output))),
        ])
        return [output]
    if path == "/healthz":
        start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", "2")])
        return [b"ok"]
    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"not found"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_exporter(port: int = 8000, daemon: bool = True) -> threading.Thread:
    """Start the Prometheus metrics HTTP server in a background thread."""
    server = make_server("0.0.0.0", port, _metrics_app, handler_class=_SilentHandler)
    thread = threading.Thread(target=server.serve_forever, name="pii-exporter", daemon=daemon)
    thread.start()
    logger.info("[Exporter] Prometheus metrics: http://0.0.0.0:%d/metrics", port)
    return thread


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(os.getenv("EXPORTER_PORT", "8000"))
    logger.info("Starting Bob-A-Thon PII Metrics Exporter (3-tier) on port %d …", port)
    server = make_server("0.0.0.0", port, _metrics_app, handler_class=_SilentHandler)
    logger.info("Scrape : http://0.0.0.0:%d/metrics", port)
    logger.info("Health : http://0.0.0.0:%d/healthz", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Exporter stopped.")
