"""
sanitizer.py — Real-Time PII Masking Logging Filter (3-Tier Business Observability)
Bob-A-Thon | IBM Bob × Developer Kaki Hackathon

Drop this filter onto any Python logging handler to automatically intercept
and mask Malaysian NRICs and PCI credit card numbers before they reach disk
or any centralised log aggregator (e.g., Elastic, Splunk, IBM QRadar).

New in this version:
  - Emits service / module blast-radius labels so Grafana Row 4 (Root-Cause
    Blast Radius) can pin the offending service, module, and logger name.
  - Delegates all Prometheus counter updates to exporter.record_interception()
    so the business-layer financial metrics (RM risk avoided, cost saved) are
    always incremented alongside the raw interception counter.

Usage:
    from sanitizer import PIISanitizingFilter, install_global_filter

    # Option A: attach to a specific handler
    handler = logging.FileHandler("app.log")
    handler.addFilter(PIISanitizingFilter(service="PaymentService", module="checkout"))
    logger.addHandler(handler)

    # Option B: instrument every handler on the root logger at startup
    install_global_filter(service="PaymentService")
"""

import logging
import os
import re
from typing import Callable, List, Tuple

# ---------------------------------------------------------------------------
# Prometheus integration (graceful no-op when exporter is not imported)
# ---------------------------------------------------------------------------
try:
    from exporter import record_interception as _record
    _HAS_EXPORTER = True
except ImportError:
    def _record(pii_type: str, service: str = "unknown", module: str = "unknown") -> None:
        pass
    _HAS_EXPORTER = False


# ---------------------------------------------------------------------------
# Substitution rules: (compiled_pattern, label, replacement_factory)
# ---------------------------------------------------------------------------

def _nric_replacer(m: re.Match) -> str:
    clean = m.group().replace("-", "")
    return f"{clean[:6]}-**-****"


def _cc_replacer(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group())
    return f"****-****-****-{digits[-4:]}"


_RULES: List[Tuple[re.Pattern, str, Callable[[re.Match], str]]] = [
    (
        re.compile(
            r"\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-]?\d{2}[-]?\d{4})\b"
        ),
        "NRIC",
        _nric_replacer,
    ),
    (
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?"
            r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)"
            r"[0-9]{12}"
            r"|3[47][0-9]{13}"
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"
            r"|6(?:011|5[0-9]{2})[0-9]{12,15}"
            r"|(?:2131|1800|35\d{3})\d{11}"
            r")\b"
        ),
        "CREDIT_CARD",
        _cc_replacer,
    ),
]


# ---------------------------------------------------------------------------
# Core Filter
# ---------------------------------------------------------------------------

class PIISanitizingFilter(logging.Filter):
    """
    A logging.Filter that mutates log record messages in-place,
    replacing any detected PII with masked equivalents.

    Blast-radius labels (service, module) are forwarded to the Prometheus
    exporter so Grafana can surface the exact offending service and module.

    Args:
        service: Logical service name (e.g. "PaymentService", "AuthService").
                 Defaults to APP_SERVICE env var, then "unknown".
        module:  Override for the Python module label. Defaults to
                 record.module (the filename without .py extension).
    """

    def __init__(self, service: str | None = None, module: str | None = None, name: str = ""):
        super().__init__(name)
        self._service = service or os.getenv("APP_SERVICE", "unknown")
        self._module_override = module  # None = derive from record.module at runtime

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        module = self._module_override or record.module or "unknown"
        sanitized, count = self._sanitize(message, self._service, module)

        if count:
            record.msg = sanitized
            record.args = ()

        return True  # always allow the record through

    @staticmethod
    def _sanitize(text: str, service: str, module: str) -> tuple[str, int]:
        """Apply all PII rules, increment Prometheus counters, return (sanitized_text, total)."""
        total = 0

        def _make_sub(label: str, replacer: Callable[[re.Match], str]):
            def _sub(m: re.Match) -> str:
                nonlocal total
                total += 1
                _record(pii_type=label, service=service, module=module)
                return replacer(m)
            return _sub

        for pattern, label, replacer in _RULES:
            text = pattern.sub(_make_sub(label, replacer), text)

        return text, total


# ---------------------------------------------------------------------------
# Convenience installer
# ---------------------------------------------------------------------------

def install_global_filter(service: str | None = None, module: str | None = None) -> None:
    """
    Attach PIISanitizingFilter to every handler on the root logger.
    Call once at application startup (e.g. in settings.py or main.py).

    Args:
        service: Logical service name forwarded as a Prometheus label.
        module:  Optional module override; defaults to per-record derivation.
    """
    root = logging.getLogger()
    pii_filter = PIISanitizingFilter(service=service, module=module)
    if not root.handlers:
        logging.basicConfig()
    for handler in root.handlers:
        handler.addFilter(pii_filter)
    logging.getLogger(__name__).info(
        "[PIISanitizer] Global PII masking filter installed on %d handler(s). service=%s",
        len(root.handlers),
        pii_filter._service,
    )
