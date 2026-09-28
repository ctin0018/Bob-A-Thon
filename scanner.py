"""
scanner.py — PII Log Leak Detector
Bob-A-Thon | IBM Bob × Developer Kaki Hackathon

Scans log files or raw strings for Malaysian NRICs and PCI credit card numbers.
Exposes findings as structured events consumable by the Prometheus exporter.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII Pattern Definitions
# ---------------------------------------------------------------------------

# Malaysian NRIC: YYMMDD-SS-NNNN  (with or without dashes)
_NRIC_PATTERN = re.compile(
    r"\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-]?\d{2}[-]?\d{4})\b"
)

# PCI credit card numbers: 13–19 digit sequences (Luhn-structurally plausible)
# Covers Visa (4), Mastercard (51-55 / 2221-2720), Amex (34/37), etc.
_CC_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?"         # Visa
    r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)"
    r"[0-9]{12}"                                # Mastercard
    r"|3[47][0-9]{13}"                          # Amex
    r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"         # Diners
    r"|6(?:011|5[0-9]{2})[0-9]{12,15}"         # Discover
    r"|(?:2131|1800|35\d{3})\d{11}"            # JCB
    r")\b"
)


@dataclass
class PIIFinding:
    """Represents a single detected PII token in a log line."""
    line_number: int
    pii_type: str           # "NRIC" | "CREDIT_CARD"
    masked_value: str       # The already-masked representation
    source: str             # File path or stream identifier


@dataclass
class ScanResult:
    """Aggregate result of a full scan operation."""
    source: str
    total_lines: int = 0
    findings: List[PIIFinding] = field(default_factory=list)

    @property
    def nric_count(self) -> int:
        return sum(1 for f in self.findings if f.pii_type == "NRIC")

    @property
    def credit_card_count(self) -> int:
        return sum(1 for f in self.findings if f.pii_type == "CREDIT_CARD")


def _mask(value: str, pii_type: str) -> str:
    """Return a masked representation preserving length and type signal."""
    if pii_type == "NRIC":
        # Keep first 6 digits (DOB), mask state + sequence: 880101-**-****
        clean = value.replace("-", "")
        return f"{clean[:6]}-**-****"
    if pii_type == "CREDIT_CARD":
        # PCI-DSS: show last 4 digits only
        digits = re.sub(r"\D", "", value)
        return f"****-****-****-{digits[-4:]}"
    return "****"


def scan_line(line: str, line_number: int, source: str = "<stream>") -> List[PIIFinding]:
    """Detect all PII tokens in a single log line and return findings."""
    findings: List[PIIFinding] = []
    for match in _NRIC_PATTERN.finditer(line):
        findings.append(PIIFinding(line_number, "NRIC", _mask(match.group(), "NRIC"), source))
    for match in _CC_PATTERN.finditer(line):
        findings.append(PIIFinding(line_number, "CREDIT_CARD", _mask(match.group(), "CREDIT_CARD"), source))
    return findings


def scan_file(path: str) -> ScanResult:
    """Scan an entire log file and return a structured ScanResult."""
    result = ScanResult(source=path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                result.total_lines += 1
                result.findings.extend(scan_line(line, lineno, path))
    except OSError as exc:
        logger.error("Failed to open %s: %s", path, exc)
    return result


def scan_text(text: str, source: str = "<inline>") -> ScanResult:
    """Scan a multi-line text string (e.g., captured exception payload)."""
    result = ScanResult(source=source)
    for lineno, line in enumerate(text.splitlines(), start=1):
        result.total_lines += 1
        result.findings.extend(scan_line(line, lineno, source))
    return result
