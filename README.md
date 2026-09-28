# Bob-A-Thon: PII Log Leak Detector & Business Observability

> **IBM Bob × Developer Kaki Hackathon**
> _Enterprise Risk Mitigation, Autonomously Generated._

---

## The Problem

Malaysian financial institutions face constant pressure under **BNM RMIT** and **PDPA** compliance mandates. Yet one of the most common audit failures is deceptively simple: a developer accidentally logs a raw object or exception payload containing a customer's **National Registration Identity Card (NRIC)** number or a **credit card number** in plaintext.

These tokens propagate instantly to centralised log aggregators — Elastic, Splunk, IBM QRadar — where they persist for months. Manual code reviews routinely miss them. By the time a compliance audit flags the leak, retroactive remediation costs are already in the hundreds of developer-hours, with regulatory fines potentially running into the millions.

**This is not a hypothetical risk. It is a weekly occurrence in production environments.**

---

## Objective

Shift telemetry hygiene **left** — intercept and mask PII at the application runtime layer, _before_ it reaches any centralised infrastructure, while providing compliance and engineering leadership with real-time observability into every interception event through a **3-Tier Business Observability Dashboard**.

---

## Solution Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Application Runtime                     │
│  Developer logs raw payload (NRIC / CC number)          │
│                        ▼                                 │
│          ┌─────────────────────────┐                     │
│          │  PIISanitizingFilter    │  ← sanitizer.py     │
│          │  (logging.Filter)       │                     │
│          │  • NRIC regex mask      │                     │
│          │  • CC regex mask        │                     │
│          │  • service/module label │                     │
│          │  • record_interception()│                     │
│          └────────────┬────────────┘                     │
│                       │ masked log record                │
│                       ▼                                  │
│          ┌─────────────────────────┐                     │
│          │   Log Handler / File    │  app.log (clean)    │
│          └─────────────────────────┘                     │
└──────────────────────────────────────────────────────────┘
                        │
           exporter.record_interception()
           increments ALL business counters atomically
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│              exporter.py — :8000/metrics                 │
│                                                          │
│  Tier 1 (Executive)                                      │
│    pii_log_interceptions_total{pii_type,service,module}  │
│    pii_regulatory_risk_avoided_rm_total                  │
│    pii_engineering_cost_saved_rm_total                   │
│    pii_compliance_hygiene_rate                           │
│                                                          │
│  Tier 2 (DevSecOps)                                      │
│    pii_mttd_seconds / pii_baseline_mttd_seconds          │
│    pii_mttr_seconds / pii_baseline_mttr_seconds          │
│    pii_active_stream_vulnerabilities                     │
│                                                          │
│  Tier 3 (SLO)                                            │
│    pii_scan_duration_seconds (histogram)                 │
│    pii_transaction_response_seconds (histogram)          │
│    pii_transaction_success_total / pii_transaction_total │
└────────────────────────┬─────────────────────────────────┘
                         │ Prometheus scrape (15s)
                         ▼
┌──────────────────────────────────────────────────────────┐
│   Grafana — 3-Tier Business Observability Dashboard      │
│                                                          │
│  ROW 1: TIER 1 — Executive & Financial Risk              │
│   [Breaches Prevented] [RM Penalty Avoided]              │
│   [Engineering Cost Saved] [Hygiene Rate] [Hours Saved]  │
│   [Interceptions over time] [NRIC vs CC donut]           │
│                                                          │
│  ROW 2: TIER 2 — Operational Velocity                    │
│   [MTTD Now] [MTTD Baseline] [MTTR Now] [MTTR Baseline]  │
│   [MTTD Ratio] [MTTR Ratio] [Active Vulnerabilities]     │
│                                                          │
│  ROW 3: TIER 3 — Service Reliability & SLO               │
│   [Masking p50] [Masking p99] [Tx P90 SLO] [Success SLO] │
│   [Transaction latency time series] [Overhead time series]│
│                                                          │
│  ROW 4: TIER 2 Detail — Blast Radius                     │
│   [Top Offending Services bar gauge]                     │
│   [Service × Module × PII Type table]                    │
└──────────────────────────────────────────────────────────┘
```

### Components — all generated by IBM Bob

| File | Purpose |
|------|---------|
| [`scanner.py`](scanner.py) | Scans log files / raw text for Malaysian NRICs and PCI credit card numbers. Returns structured `PIIFinding` objects. |
| [`sanitizer.py`](sanitizer.py) | `logging.Filter` subclass that masks PII in real-time, emits service/module blast-radius labels, and delegates to `exporter.record_interception()`. |
| [`exporter.py`](exporter.py) | Prometheus exporter on `:8000/metrics`. Exposes all 3-tier metrics including RM financial counters, MTTD/MTTR gauges, SLO histograms. |
| [`grafana/dashboard.json`](grafana/dashboard.json) | Complete 4-row, 20-panel Grafana dashboard (uid `bob-a-thon-pii-v1`, 10s refresh, KL timezone). |
| [`bob_run.sh`](bob_run.sh) | End-to-end orchestration: invokes IBM Bob for each artefact, starts the exporter, imports the Grafana dashboard, commits, and pushes. |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/ctin0018/Bob-A-Thon.git && cd Bob-A-Thon

# 2. Install dependencies
pip install prometheus_client

# 3. Start the exporter
python exporter.py

# 4. Drop the sanitizer into your application
python - <<'EOF'
import logging
from sanitizer import install_global_filter

install_global_filter(service="PaymentService")

logger = logging.getLogger("demo")
logger.warning("Customer NRIC: 880101-14-5678 paid with card 4111111111111111")
# Output: Customer NRIC: 880101-**-**** paid with card ****-****-****-1111
# Prometheus: pii_log_interceptions_total{pii_type="NRIC",service="PaymentService",...} += 1
#             pii_regulatory_risk_avoided_rm_total += 50000
#             pii_engineering_cost_saved_rm_total  += 32000
EOF
```

---

## Grafana Dashboard — 3-Tier Framework

Import `grafana/dashboard.json` via **Dashboards → Import**, select your Prometheus datasource.

### Tier 1 — Executive & Financial Risk (Value Realization Layer)

| Panel | PromQL | Purpose |
|-------|--------|---------|
| Total PII Breaches Prevented | `sum(pii_log_interceptions_total)` | North Star headline |
| Regulatory Penalty Avoided (RM) | `pii_regulatory_risk_avoided_rm_total` | RM 50k × incidents |
| Engineering Cost Saved (RM) | `pii_engineering_cost_saved_rm_total` | 16h × 4 eng × RM500/hr |
| Compliance Hygiene Rate | `pii_compliance_hygiene_rate` | Target: 100% |
| Developer Hours Saved | `sum(pii_log_interceptions_total) * 0.05` | Est. hours reclaimed |

### Tier 2 — Operational Velocity (SRE / DevSecOps Layer)

| Panel | PromQL | Purpose |
|-------|--------|---------|
| MTTD — Now | `pii_mttd_seconds` | < 1s inline detection |
| MTTD — Baseline | `pii_baseline_mttd_seconds` | 14 days (audit baseline) |
| MTTR — Now | `pii_mttr_seconds` | 10 min (Bob auto-patch) |
| MTTR — Baseline | `pii_baseline_mttr_seconds` | 127 min (hotfix baseline) |
| MTTD Improvement | `pii_baseline_mttd_seconds / clamp_min(pii_mttd_seconds, 0.001)` | 1.2M× faster |
| MTTR Improvement | `pii_baseline_mttr_seconds / clamp_min(pii_mttr_seconds, 1)` | 12.7× faster |
| Active Vulnerabilities | `pii_active_stream_vulnerabilities` | Open blast-radius streams |
| Top Services (Blast Radius) | `sort_desc(sum by (service) (pii_log_interceptions_total))` | Offending services |
| Blast Radius Table | `sum by (service, module, pii_type) (pii_log_interceptions_total)` | Exact remediation targets |

### Tier 3 — Service Reliability & SLO (Application & User Journey Layer)

| Panel | PromQL | SLO |
|-------|--------|-----|
| Masking Overhead p50 | `histogram_quantile(0.50, …pii_scan_duration_seconds_bucket…)` | < 0.5ms |
| Masking Overhead p99 | `histogram_quantile(0.99, …pii_scan_duration_seconds_bucket…)` | < 0.5ms |
| Transaction Response P90 | `histogram_quantile(0.90, …pii_transaction_response_seconds_bucket…)` | < 2.0s |
| Service Success Rate | `sum(rate(success[5m])) / sum(rate(total[5m]))` | ≥ 99.9% |

---

## The 3-Tier Framework Explained

```
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Executive & Financial Risk (The "Value Realization" Layer)     │
│  Total PII Breaches Prevented  | Regulatory Penalty Avoided (RM)      │
│  Engineering Man-Hours Saved   | Compliance Pass Rate (BNM / PDPA)    │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 2: Operational Velocity (The SRE / DevSecOps Layer)               │
│  MTTD (Detection Latency)      | MTTR (Remediation Latency)           │
│  Active Log Stream Vulnerabilities Intercepted                         │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 3: Core Service Reliability (The Application & User Journey Layer)│
│  Masking Latency Overhead      | Transaction Response Time SLO        │
│  Application Success Rate SLO  | Throughput (Req/Sec)                 │
└────────────────────────────────────────────────────────────────────────┘
```

**Why this matters to judges:**
- **Tier 1** speaks to CIOs/CISOs — it converts raw intercept counts into RM financial exposure and compliance pass rates that appear directly in board reports.
- **Tier 2** speaks to SRE / DevSecOps leads — MTTD dropping from 14 days to 1 second and MTTR dropping from 127 minutes to 10 minutes are the exact efficiency metrics that justify toolchain investment.
- **Tier 3** speaks to engineering leads — it proves the security control is _transparent_ to users: no latency regression, no dropped transactions, no SLO degradation.

---

## Business Impact & North Star Metrics

### Regulatory Cost Avoidance
Under BNM RMIT and PDPA, each unmasked NRIC or PAN in a log aggregator = one audit finding. Estimated average remediation cost: **RM 50,000 per incident** (audit fee + legal + engineering time). The dashboard tracks this cumulatively in real-time.

### Engineering Efficiency Formula
```
Cost Saved = ΔMTTR Hours × Engineers Involved × Hourly Rate
           = 16h × 4 engineers × RM 500/hr
           = RM 32,000 per incident avoided
```

### Before → Now → Future

| Dimension | Before IBM Bob | Now (Bob + Sanitizer) | Improvement |
|-----------|---------------|----------------------|-------------|
| MTTD | 14 days (audit) | < 1 second (inline) | **1,209,600×** |
| MTTR | 127 minutes (hotfix) | 10 minutes (Bob patch) | **12.7×** |
| Compliance Hygiene | Manual, periodic | 100% automated, real-time | **∞** |
| Cost Per Incident | RM 32,000–50,000 | RM 0 (prevented) | **100% avoidance** |

---

## The Pitch Hook

> _"Malaysian financial institutions spend millions maintaining BNM RMIT compliance, yet a single developer accidentally logging a raw NRIC payload can trigger a massive audit failure. We used IBM Bob to solve this in 20 minutes. Bob autonomously generated a deterministic PII masking filter and a Prometheus exporter. We routed that telemetry into a Grafana dashboard that speaks three languages simultaneously: the RM risk language of the CFO, the MTTD/MTTR language of the SRE, and the SLO language of the engineering lead. IBM Bob isn't just a coding copilot — it is an enterprise risk-mitigation engine."_

---

## Compliance Coverage

| Regulation | Requirement Addressed |
|------------|-----------------------|
| **BNM RMIT** | Data confidentiality controls; prevention of unauthorised disclosure |
| **PDPA Malaysia** | Protection of personal data (NRIC = sensitive personal data under PDPA s.4) |
| **PCI-DSS** | Requirement 3.3 — mask PAN; log masking prevents storage of full card data |

---

## License

MIT © 2025 Bob-A-Thon Contributors
