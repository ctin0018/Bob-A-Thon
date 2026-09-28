"""
exporter.py — Prometheus Metrics Exporter
Bob-A-Thon | IBM Bob × Developer Kaki Hackathon

Exposes PII interception telemetry on :8000/metrics in Prometheus text format.
Grafana scrapes this endpoint to populate the Business Observability dashboard.

Metrics published:
  pii_log_interceptions_total{pii_type}  — cumulative interceptions by type
  pii_scan_duration_seconds              — histogram of scan latency
  pii_active_scanner_info                — gauge with version/build label

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
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Metric definitions (shared with sanitizer.py via REGISTRY)
# ---------------------------------------------------------------------------

PII_INTERCEPTED = Counter(
    "pii_log_interceptions_total",
    "Total PII tokens intercepted and masked before log write",
    ["pii_type"],
    registry=REGISTRY,
)

PII_SCAN_DURATION = Histogram(
    "pii_scan_duration_seconds",
    "Latency of individual log-line scan operations",
    buckets=[0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0],
    registry=REGISTRY,
)

PII_SCANNER_INFO = Gauge(
    "pii_active_scanner_info",
    "Metadata about the running PII scanner instance",
    ["version", "environment"],
    registry=REGISTRY,
)

# Seed the info gauge so it appears in Grafana even before first interception
_VERSION = os.getenv("APP_VERSION", "1.0.0")
_ENV = os.getenv("APP_ENV", "production")
PII_SCANNER_INFO.labels(version=_VERSION, environment=_ENV).set(1)

# Pre-initialise label series so dashboards show zero, not "no data"
PII_INTERCEPTED.labels(pii_type="NRIC")
PII_INTERCEPTED.labels(pii_type="CREDIT_CARD")


# ---------------------------------------------------------------------------
# Lightweight WSGI app (avoids pulling in Flask for a single endpoint)
# ---------------------------------------------------------------------------

class _SilentHandler(WSGIRequestHandler):
    """Suppress per-request access logs to keep stdout clean."""
    def log_message(self, *args):  # noqa: D401
        pass


def _metrics_app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    if path == "/metrics":
        output = generate_latest(REGISTRY)
        start_response(
            "200 OK",
            [
                ("Content-Type", CONTENT_TYPE_LATEST),
                ("Content-Length", str(len(output))),
            ],
        )
        return [output]

    if path == "/healthz":
        body = b"ok"
        start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", "2")])
        return [body]

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"not found"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_exporter(port: int = 8000, daemon: bool = True) -> threading.Thread:
    """
    Start the Prometheus metrics HTTP server in a background thread.

    Args:
        port:   TCP port to listen on (default 8000).
        daemon: If True the thread exits when the main process does.

    Returns:
        The running Thread object.
    """
    server = make_server("0.0.0.0", port, _metrics_app, handler_class=_SilentHandler)
    thread = threading.Thread(target=server.serve_forever, name="pii-exporter", daemon=daemon)
    thread.start()
    logger.info("[Exporter] Prometheus metrics available at http://0.0.0.0:%d/metrics", port)
    return thread


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    port = int(os.getenv("EXPORTER_PORT", "8000"))
    logger.info("Starting Bob-A-Thon PII Metrics Exporter on port %d …", port)

    # Run in the foreground when invoked directly
    server = make_server("0.0.0.0", port, _metrics_app, handler_class=_SilentHandler)
    logger.info("Prometheus scrape endpoint: http://0.0.0.0:%d/metrics", port)
    logger.info("Health check endpoint:      http://0.0.0.0:%d/healthz", port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Exporter stopped.")
