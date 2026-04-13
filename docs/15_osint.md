# OSINT Integration (AbuseIPDB & VirusTotal)

This document describes how **open-source intelligence (OSINT)** is used in **nal**: which third-party APIs are called, how requests and caching behave, and—critically—how those results combine with the **machine-learning anomaly pipeline** before data is stored and shown on the **OSINT Validation** UI.

---

## 1. Role of OSINT in the overall system

Network flows are first analyzed **locally** with ML on flow features (CICFlowMeter-style columns). OSINT does **not** decide whether a flow is anomalous. It **enriches** flows that the **unsupervised anomaly detector** has already flagged, by asking external services: *“What do AbuseIPDB and VirusTotal know about this public IP?”*

That split keeps API cost and latency bounded: third-party lookups run only when local models say *something looks unusual*, and only for a **single chosen IP** per flow.

| Tool | Role in this project |
|------|----------------------|
| **AbuseIPDB** | Community-driven IP reputation: reports of abusive behavior (spam, attacks, scanning) with a confidence score. |
| **VirusTotal** | Aggregated antivirus / sandbox verdicts for an IP: how many engines flag it as malicious vs harmless, etc. |

Together they add **global reputation** (AbuseIPDB) and **multi-vendor detection context** (VirusTotal). The **random forest** (supervised) label and confidence still drive **classification**, **risk_score**, and **risk_level**; OSINT feeds **`final_score`** and **`final_verdict`** for triage on the OSINT page.

---

## 2. End-to-end pipeline: from PCAP/CSV to OSINT verdict

Conceptually, processing looks like this:

1. **Input**: PCAP/PCAPNG (converted with CICFlowMeter) or CSV of flow records.
2. **Feature prep**: Rows are cleaned (`clean_data`), aligned to training **`feature_names`** when present, then scaled with the persisted **`scaler.pkl`** when available.
3. **Supervised path (optional)**: If **`rf_model.pkl`** and **`label_encoder.pkl`** exist, the random forest predicts attack vs benign labels and **max class probability** as **confidence**. If the supervised model is missing, every flow is labeled **BENIGN** for classification purposes, with a placeholder confidence—anomaly-only mode still works.
4. **Unsupervised path**: If **`if_model.pkl`** (Isolation Forest) is loaded, each row gets:
   - **`anomaly_score`**: derived from `decision_function`, mapped into **[0, 1]** via `0.5 - raw` then clipped (higher = more “anomalous” in this scaling).
   - **`is_anomaly`**: `True` when `predict(...) == -1` (outlier in training space).
5. **OSINT gate**: If **`is_anomaly`** is **false**, no OSINT runs for that flow (no external calls, no OSINT columns beyond what the DB defaults provide).
6. **IP selection**: If **`is_anomaly`** is **true**, `_pick_osint_ip` scans **source then destination** and returns the **first globally routable** IPv4/IPv6 (`ipaddress.is_global`). If neither is public and **`OSINT_SKIP_NON_PUBLIC_IPS`** is on (default), the flow gets **`OSINT Skipped`** without calling vendors.
7. **External lookups**: **`run_osint_checks`** calls AbuseIPDB, then VirusTotal (see below), with caching and retries.
8. **Blend**: When at least one provider succeeds, **`final_score`** blends **ML (anomaly) + abuse + VT**; **`final_verdict`** is a human-readable bucket. Results are persisted on the flow row and exposed via **`GET /api/osint/flows`** and the **`/osint`** page.

The same OSINT block runs in **batch file analysis** (`analyze_file`) and in the **realtime** path that builds per-flow rows from a live dataframe.

---

## 3. How OSINT relates to the ML models (important detail)

In code, the value passed into **`compute_final_score`** as **`ml_confidence`** is **not** the random forest’s classification confidence. It is:

\[
\text{ml\_confidence} = \mathrm{clip}(\text{anomaly\_score}, 0, 1) \times 100
\]

So the **60%** weight in the final blend is tied to the **Isolation Forest anomaly signal** (scaled to 0–100), not to **`confidence`** from supervised **`predict_proba`**.

**Why that design matters**

- **Isolation Forest** answers: *“Is this flow unusual compared to normal traffic in feature space?”*
- **AbuseIPDB / VirusTotal** answer: *“Is this IP broadly associated with abuse or malicious verdicts?”*

Those questions are complementary. Feeding the anomaly strength into the same 0–100 space as abuse and VT scores yields a single **`final_score`** for analyst triage without overwriting the separate **risk_score** / **risk_level** logic that mixes supervised confidence and anomaly when a supervised model is present.

**What the random forest still does**

- Produces **`classification`**, **`confidence`**, and (with the anomaly override) refined **`threat_type`** when an anomaly is labeled BENIGN by RF but flagged by IF.
- Contributes to **`risk_score`** via the usual hybrid formulas in **`decision_service.py`**.

OSINT does **not** retrain or call into either model; it is a **post-anomaly enrichment** step.

---

## 4. External APIs (exact endpoints and behavior)

### 4.1 AbuseIPDB

| Aspect | Detail |
|--------|--------|
| **Product** | Crowdsourced IP abuse reports with AbuseIPDB’s own confidence metric. |
| **HTTP** | `GET https://api.abuseipdb.com/api/v2/check` |
| **Auth** | API key in header **`Key`**. |
| **Query params** (as implemented) | `ipAddress`, `maxAgeInDays=90`, `verbose` |
| **Success** | HTTP 2xx, JSON parse OK, read `data.abuseConfidenceScore` → **`abuse_score`** (0–100). |
| **Failure** | Missing **`ABUSEIPDB_API_KEY`**, HTTP 4xx/5xx, network error → **`abuse_ok=false`**, score omitted. |

Implementation: **`check_abuseipdb`** in **`nal/backend/app/services/osint.py`**.

### 4.2 VirusTotal

| Aspect | Detail |
|--------|--------|
| **Product** | Many vendors’ last analysis stats for the IP object. |
| **HTTP** | `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` |
| **Auth** | API key in header **`x-apikey`**. |
| **Score** | From `data.attributes.last_analysis_stats`: sums `malicious`, `harmless`, `suspicious`, `undetected`, `timeout`; then **`vt_score = (malicious / total) * 100`** when `total > 0`, else **0** when stats exist with zero total. |
| **Success** | HTTP 2xx and parsable stats → **`vt_ok=true`**. |
| **Failure** | Missing **`VIRUSTOTAL_API_KEY`**, HTTP errors, parse issues → **`vt_ok=false`**. |

Implementation: **`check_virustotal`** in **`nal/backend/app/services/osint.py`**.

### 4.3 Shared client behavior

- **Library**: **`requests`**, **10 s** timeout per call.
- **Order**: AbuseIPDB first, then VirusTotal inside **`run_osint_checks`**.
- **HTTP 429**: Reads **`Retry-After`** when present (sleep that many seconds); otherwise sleeps **2 s**, then retries the loop.
- **5xx / network**: Up to **`OSINT_MAX_RETRIES`** (default **2**) with backoff.
- **Master switch**: **`OSINT_ENABLED=false`** returns immediately with **`OSINT disabled`** and no HTTP calls.
- **Non-public IPs**: When **`OSINT_SKIP_NON_PUBLIC_IPS`** is true, **`run_osint_checks`** returns **`non-public ip (skipped)`** before any vendor call (defense in depth beside **`_pick_osint_ip`** in **`decision_service.py`**).

---

## 5. Caching

OSINT uses a **process-local, in-memory** map: IP → **`(expiry_epoch, OsintResult)`**.

- **TTL**: **`OSINT_CACHE_TTL_SECONDS`** (default **3600**).
- **If TTL ≤ 0**: **`_cache_set`** does nothing—results are **not** cached (every anomaly hit can trigger fresh API calls).

Repeated anomalies involving the same public IP within the TTL reuse the same **`abuse_score`**, **`vt_score`**, and raw payloads without new HTTP requests.

---

## 6. Combining scores and verdicts

### 6.1 Weighted blend

When **at least one** of AbuseIPDB or VirusTotal reports **`ok`**, **`compute_final_score`** runs:

\[
\text{final} = 0.6 \times \text{ml\_confidence} + 0.2 \times \text{abuse\_score} + 0.2 \times \text{vt\_score}
\]

- **`ml_confidence`**: 0–100 from **clipped anomaly_score** (Isolation Forest), as above.
- **Missing OSINT components**: Treated as **0.0** in the sum (so a partial success still produces a number; comment in code describes this as conservative for absent legs).

Result is clamped to **[0, 100]**.

### 6.2 Verdict labels

**`osint_verdict_from_final_score`**:

| Condition | **`final_verdict`** |
|-----------|---------------------|
| `final_score > 70` | **Verified Threat** |
| `40 ≤ final_score ≤ 70` | **Suspicious** |
| `final_score < 40` | **Likely False Positive** |

### 6.3 Special cases

| Situation | **`final_score`** | **`final_verdict`** |
|-----------|-------------------|---------------------|
| Both **`abuse_ok`** and **`vt_ok`** are false | **`null`** (unset) | **OSINT Unavailable** |
| No public IP to query | **`null`** | **OSINT Skipped** |
| OSINT disabled / non-public at service layer | Handled in **`run_osint_checks`**; decision layer still sets skip/unavailable style messages as appropriate |

This avoids treating “API failed” as “score 0” (benign), which would mislead analysts.

---

## 7. Code locations (quick reference)

| Piece | Location |
|-------|----------|
| HTTP clients, cache, **`compute_final_score`**, verdict helper | `nal/backend/app/services/osint.py` |
| When OSINT runs; IP pick; **`ml_confidence`** from **`anom_score`** | `nal/backend/app/services/decision_service.py` |
| Env toggles and API keys | `nal/backend/app/config.py` |
| REST: **`GET /api/osint/flows`** | `nal/backend/app/osint_routes.py` |
| Persistence / listing | `nal/backend/app/db.py` (`get_osint_flows`, flow columns) |
| UI | `nal/frontend/src/pages/OSINTValidation.jsx`, route **`/osint`** |

---

## 8. Configuration (environment)

Set these in the environment or `.env` (see **`config.py`** for parsing):

| Variable | Purpose |
|----------|---------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key. |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key. |
| `OSINT_ENABLED` | Master switch (default on). |
| `OSINT_CACHE_TTL_SECONDS` | Per-IP cache lifetime; **0** disables caching. |
| `OSINT_MAX_RETRIES` | Retries on transient failures / rate limits. |
| `OSINT_SKIP_NON_PUBLIC_IPS` | Skip non-global IPs (default on). |

Restart the backend after changing keys or **`OSINT_*`** variables.

---

## 9. Operational notes

- **Quotas**: Both vendors enforce rate and daily/monthly limits; **anomaly-only** triggering plus **TTL cache** reduce volume.
- **Privacy**: Only the **chosen public IP** (src preferred, then dst) is sent to third parties when skipping is enabled—not full payloads or flow contents.
- **No training feedback loop**: OSINT outcomes are **not** written back into **`if_model.pkl`** or **`rf_model.pkl`** in this codebase; they are **operational enrichment** for review.

---

## 10. Summary

| Source | What nal uses it for |
|--------|----------------------|
| **Isolation Forest** | **`is_anomaly`**, **`anomaly_score`** → scaled to **`ml_confidence`** (0–100) for **`final_score`**. |
| **Random Forest** (if present) | **Classification**, **confidence**, **risk_score** / **risk_level**—parallel to OSINT, not inside **`compute_final_score`**. |
| **AbuseIPDB API v2** | **`abuse_score`** 0–100 from **`abuseConfidenceScore`**. |
| **VirusTotal API v3** | **`vt_score`** 0–100 from malicious ratio over **`last_analysis_stats`**. |

Together, AbuseIPDB and VirusTotal feed a **weighted score** with the **anomaly model’s strength** and drive **verdict** text for the OSINT Validation workflow, while lookups stay **scoped to anomalies**, **cached**, and **skipped** for non-public IPs by default.
