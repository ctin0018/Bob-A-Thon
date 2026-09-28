"""
sanitizer.py — Real-Time PII Masking Logging Filter
Bob-A-Thon | IBM Bob × Developer Kaki Hackathon

Drop this filter onto any Python logging handler to automatically intercept
and mask Malaysian NRICs and PCI credit card numbers before they reach disk
or any centralised log aggregator (e.g., Elastic, Splunk, IBM QRadar).

Usage:
    from sanitizer import PIISanitizingFilter, install_global_filter

    # Option A: attach to a specific handler
    handler = logging.FileHandler("app.log")
    handler.addFilter(PIISanitizingFilter())
    logger.addHandler(handler)

    # Option B: instrument every handler on the root logger at startup
    install_global_filter()
"""

import logging
import re
from typing import Callable, List, Tuple

try:
    from prometheus_client import Counter
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Metric registration (no-op when prometheus_client is absent)
# ---------------------------------------------------------------------------
if _PROMETHEUS_AVAILABLE:
    PII_INTERCEPTED = Counter(
        "pii_log_interceptions_total",
        "Total PII tokens intercepted and masked before log write",
        ["pii_type"],
    )
else:
    class _NoOpCounter:
        def labels(self, **_):
            return self
        def inc(self, *_, **__):
            pass
    PII_INTERCEPTED = _NoOpCounter()  # type: ignore[assignment]


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
    replacing any detected PII with masked equivalents and incrementing
    the Prometheus interception counter for each substitution.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Stringify the message so formatters receive clean output
        message = record.getMessage()
        sanitized, count = self._sanitize(message)

        if count:
            # Patch the record so the final formatter emits the masked string
            record.msg = sanitized
            record.args = ()  # args already merged into msg above

        return True  # always allow the record through (just sanitized)

    @staticmethod
    def _sanitize(text: str) -> Tuple[str, int]:
        """Apply all PII rules, return (sanitized_text, total_replacements)."""
        total = 0

        def _make_sub(label: str, replacer: Callable[[re.Match], str]):
            def _sub(m: re.Match) -> str:
                nonlocal total
                total += 1
                PII_INTERCEPTED.labels(pii_type=label).inc()
                return replacer(m)
            return _sub

        for pattern, label, replacer in _RULES:
            text = pattern.sub(_make_sub(label, replacer), text)

        return text, total


# ---------------------------------------------------------------------------
# Convenience installer
# ---------------------------------------------------------------------------

def install_global_filter() -> None:
    """
    Attach PIISanitizingFilter to every existing handler on the root logger.
    Call this once at application startup (e.g., in settings.py or main.py).
    """
    root = logging.getLogger()
    pii_filter = PIISanitizingFilter()
    if not root.handlers:
        # Ensure at least a basic handler exists so the filter is reachable
        logging.basicConfig()
    for handler in root.handlers:
        handler.addFilter(pii_filter)
    logging.getLogger(__name__).info(
        "[PIISanitizer] Global PII masking filter installed on %d handler(s).",
        len(root.handlers),
    )
