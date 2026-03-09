# Live (Active) Monitoring — Current Implementation (Detailed)

This document describes **in detail** how live/active packet monitoring is implemented in this project: capture, flow building, classification, storage, APIs, and frontend behavior.

---

## 1. Overview

- **Purpose:** Capture live network packets on a chosen interface, aggregate them into **flows**, classify each flow (benign vs. anomaly/attack type) using the same decision pipeline as passive uploads, and store flows in the same SQLite database with `monitor_type = 'active'`. The Dashboard can then show stats filtered by passive or active.
- **Capture:** Scapy `sniff()` on a configurable interface (default: loopback `lo` for local API traffic). Requires **root/sudo** on the backend for raw packet capture.
- **Processing:** Background thread; does not block the FastAPI event loop. Loop: capture → build flows from packets → classify → insert into DB.
- **Storage:** Same `flows` table as passive analysis; `monitor_type` column distinguishes `'passive'` (file uploads) from `'active'` (realtime).

---

## 2. Backend: Realtime service (capture and flow building)

**Module:** `nal/backend/app/services/realtime_service.py`

### 2.1 Global state and throttling

- **`_last_capture_error`:** Module-level optional string. Set when capture fails (e.g. permission denied, interface not found); cleared on successful capture. Exposed in status so the UI can show “Capture error”.
- **`_capture_fail_log_time`, `_capture_fail_count`:** Used to throttle repeated failure logs (e.g. log at most once per 30 seconds) to avoid log spam.

### 2.2 `capture_packets(interface, duration=5) -> list of packets`

- **Interface:**
  - If `interface` is empty or whitespace, the effective interface is **`"lo"`** (loopback), so local frontend–backend API traffic is captured when using “Default”.
  - Otherwise the given string is used (e.g. `"eth0"`, `"lo"`).
- **Scapy:** Uses `scapy.all.sniff(iface=iface, timeout=duration, count=MAX_PACKETS_PER_WINDOW)`. `MAX_PACKETS_PER_WINDOW = 50000` to limit memory.
- **Exceptions:**
  - **ImportError (scapy missing):** Sets `_last_capture_error` to a message, returns `[]`.
  - **Interface not found / no such device:** Retries with `iface=None` (Scapy default). On retry success, clears `_last_capture_error` and returns packets. On retry failure, sets `_last_capture_error` to the exception string, throttles log, returns `[]`.
  - **Other errors (e.g. Operation not permitted):** Sets `_last_capture_error`, throttles log, returns `[]`.
- **Success:** Clears `_last_capture_error` and returns the list of packets.

So the UI can show the exact capture error when capture keeps failing (e.g. “Run backend with sudo”).

---

## 3. Flow building from packets

### 3.1 `build_flows_from_packets(packets) -> list of flow dicts`

- **Input:** List of Scapy packets (typically with IP and TCP/UDP/ICMP).
- **Logic:**
  - Only packets with an IP layer (IPv4 or IPv6) are considered; others skipped.
  - **Flow key:** Normalized bidirectional 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`. The “smaller” (src_ip, src_port) vs (dst_ip, dst_port) is chosen as the first pair so both directions of a connection map to the same flow.
  - **Protocol:** Inferred from layers: TCP → 6, UDP → 17, ICMP → 1; others skipped (no flow entry). Protocol name is later mapped via `PROTOCOL_MAP` (e.g. 6 → "TCP").
  - Per flow, aggregates: forward/backward packet counts and byte counts, SYN flag count (TCP), and timestamps for duration.
- **Output:** List of dicts compatible with the decision engine:
  - `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` (string, e.g. "TCP"),
  - `duration`, `total_fwd_packets`, `total_bwd_packets`, `total_length_fwd`, `total_length_bwd`,
  - `flow_bytes_per_sec`, `flow_packets_per_sec`, `syn_flag_count`.

These field names match what `decision_engine.classify_flows()` expects for realtime flows.

---

## 4. RealtimeMonitor class (background loop)

### 4.1 State

- **`running`:** Boolean; whether the capture loop should keep running.
- **`interface`:** String or None; the interface passed at start (for status display).
- **`_thread`:** The background thread running `_run`.
- **`_lock`:** Protects `running`, `interface`, `_thread`, `_capture_count`, `_last_flow_count`.
- **`_capture_count`:** Number of successful “capture windows” that produced at least one inserted batch.
- **`_last_flow_count`:** Number of flows in the last successfully inserted batch.

### 4.2 `start(interface)`

- Called from the API in a separate daemon thread (so the HTTP handler returns immediately).
- If already `running`, returns without starting a second loop.
- Sets `running = True`, stores `interface` (or None), starts a **daemon** thread that runs `_run(interface)`.

### 4.3 `_run(interface)` (main loop)

- **Loop:** While `running`:
  1. **Capture:** `capture_packets(interface, duration=5)`.
  2. If no packets, `continue`.
  3. **Build flows:** `build_flows_from_packets(packets)`.
  4. If no flows, `continue`.
  5. **Classify:** `decision_engine.classify_flows(flows_raw)` (same service used for uploaded CSV/pcap analysis). Returns enriched flow dicts with classification, risk_score, etc.
  6. If no enriched flows, `continue`.
  7. **Enrich for DB:** For each flow: set `monitor_type = "active"`, `analysis_id = None`, `upload_filename = "realtime"`, `id` (short UUID), `timestamp` (UTC ISO).
  8. **Insert:** `db.insert_flows(enriched, monitor_type="active")`.
  9. Update `_capture_count` and `_last_flow_count`; log at debug level.
- Any exception in the loop is logged with traceback; the loop continues (no crash).

So every ~5 seconds (plus processing time) a new capture window runs; packets become flows, flows are classified, then written to the DB as active.

### 4.4 `stop()`

- Sets `running = False`. The thread’s next loop iteration exits; no explicit join (daemon thread).

### 4.5 `get_status() -> dict`

- Returns: `running`, `interface` (or `"lo (default)"` when None), `capture_count`, `last_flow_count`, `capture_error` (= `_last_capture_error`). Used by the status API.

---

## 5. Decision engine (classification)

**Module:** `nal/backend/app/services/decision_service.py`

- **`classify_flows(flows_raw)`:** Accepts list of flow dicts with the keys produced by `build_flows_from_packets` (and CIC-style names used internally: Source IP, Destination Port, Flow Duration, etc.). Uses the same models and logic as for passive analysis (Random Forest if available, Isolation Forest for anomaly score, risk and threat inference). Returns list of enriched flow dicts including `classification`, `confidence`, `anomaly_score`, `risk_score`, `risk_level`, `is_anomaly`, etc. If the supervised model is missing, only unsupervised/anomaly path is used (as documented in startup logs).

---

## 6. Database: flows and monitor_type

**Module:** `nal/backend/app/db.py`

- **`flows` table:** Has a `monitor_type` column (default `'passive'`). Schema upgrades add it if missing.
- **`insert_flows(flows, monitor_type="passive")`:** Inserts each flow; each row gets `monitor_type` from the flow dict or the argument (realtime service passes `"active"`).
- **`get_dashboard_stats(monitor_type=None)`:** Aggregates (total_flows, total_anomalies, avg_risk_score, attack_distribution, risk_distribution, timeline, protocols, etc.). If `monitor_type` is `'passive'` or `'active'`, the query adds `WHERE COALESCE(monitor_type, 'passive') = ?` so the Dashboard can show either passive-only or active-only stats.
- **`get_flow_counts_by_monitor_type()`:** Returns counts per `monitor_type` (e.g. `{"active": 0, "passive": 17139}`). Used by the status API so the UI can show “Total in DB (active / passive)”.

---

## 7. Backend API endpoints (realtime)

**Location:** `nal/backend/app/main.py`

- **`POST /api/realtime/start?interface=`**  
  - Query param: `interface` (optional).  
  - If monitor already running, returns `{ "status": "error", "message": "Already running" }`.  
  - Otherwise starts the monitor in a daemon thread: `realtime_monitor.start(interface or "")`.  
  - Returns `{ "status": "started", "interface": ... }`.

- **`POST /api/realtime/stop`**  
  - Calls `realtime_monitor.stop()`.  
  - Returns `{ "status": "stopped" }`.

- **`GET /api/realtime/status`**  
  - Returns `realtime_monitor.get_status()` plus flow counts: `db.get_flow_counts_by_monitor_type()` merged into the response as `flow_counts` (e.g. `{ "active": n, "passive": m }`). So the response includes `running`, `interface`, `capture_count`, `last_flow_count`, `capture_error`, `flow_counts`.

- **`GET /api/realtime/interfaces`**  
  - Returns a list of interface names **that Scapy can use** for capture: `scapy.all.get_if_list()`. This avoids offering interfaces that Scapy does not see (e.g. some virtual interfaces), which previously caused “interface not found” when the user selected one. Fallback: if Scapy fails, use `psutil.net_if_addrs().keys()`; if that fails, return `["lo", "eth0", "wlan0"]`.

---

## 8. Dashboard stats and passive/active toggle

- **`GET /api/dashboard/stats?monitor_type=passive|active`**  
  - Calls `db.get_dashboard_stats(monitor_type)` with the given query param.  
  - Frontend Dashboard uses this to show either “Passive” (file uploads) or “Active” (live) stats; same KPIs and charts, filtered by `monitor_type`.

---

## 9. Frontend: Active Monitoring page

**Route:** e.g. `/active-monitoring` (or as configured in the app).  
**Component:** `nal/frontend/src/pages/ActiveMonitoring.jsx`

### 9.1 Data loading

- On mount: fetches **status** (`getRealtimeStatus()` → `GET /api/realtime/status`) and **interfaces** (`getRealtimeInterfaces()` → `GET /api/realtime/interfaces`). Interfaces populate a dropdown; if none selected, first interface is auto-selected.
- **Polling:** When `status.running` is true, status is refetched every **2 seconds**; when stopped, every **5 seconds**. So “Capture Windows”, “Last Batch Flows”, “Total in DB (active/passive)” and “Capture error” update live.

### 9.2 Controls

- **Interface dropdown:** Options: “Default (lo – captures local API traffic)” (value `""`) plus one option per item from `/api/realtime/interfaces`. When “Default” is selected, backend uses `lo`.
- **Start button:** Calls `startRealtimeMonitor(selectedInterface)` (POST `/api/realtime/start` with query `interface=...`). Disabled while running or while a request is in progress. On success, refetches status.
- **Stop button:** Calls `stopRealtimeMonitor()` (POST `/api/realtime/stop`). Disabled when not running.

### 9.3 Status display

- **State:** Running (with green pulse) or Stopped.
- **Interface:** From status (e.g. `lo (default)` when default was used).
- **Capture Windows:** `status.capture_count`.
- **Last Batch Flows:** `status.last_flow_count`.
- **Total in DB (active / passive):** `status.flow_counts.active` and `status.flow_counts.passive`.
- **Capture error:** If `status.capture_error` is set, a red box shows the message and reminds the user to run the backend with sudo.
- When running but active count is 0 and there is no capture error, a short message explains that capture is on loopback and suggests using the app (e.g. refresh Dashboard) to generate traffic.
- When stopped, a line tells the user to click Start to begin live capture and that the backend must run with sudo.

### 9.4 Note box

- Explains that active monitoring captures on the selected interface, classifies flows, and inserts them with `monitor_type=active`; that the Dashboard can show aggregated data for both passive and active; and that the backend must be run with sudo for live capture, with the exact command:  
  `cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`

---

## 10. Frontend API client (realtime)

**File:** `nal/frontend/src/services/api.js`

- `startRealtimeMonitor(iface)` → POST `/api/realtime/start` with `params: { interface: iface }`
- `stopRealtimeMonitor()` → POST `/api/realtime/stop`
- `getRealtimeStatus()` → GET `/api/realtime/status`
- `getRealtimeInterfaces()` → GET `/api/realtime/interfaces`

---

## 11. End-to-end data flow (active)

| Step | Where | What |
|------|--------|------|
| User selects interface | ActiveMonitoring.jsx | Dropdown: Default (lo) or from GET /api/realtime/interfaces |
| User clicks Start | Frontend | POST /api/realtime/start?interface=... |
| Backend starts thread | main.py | realtime_monitor.start(interface) in daemon thread |
| Loop: capture | realtime_service.py | sniff(iface=lo or given, timeout=5, count=50000) |
| Loop: build flows | realtime_service.py | build_flows_from_packets(packets) → list of flow dicts |
| Loop: classify | decision_service.py | classify_flows(flows_raw) → enriched flows |
| Loop: insert | db.py | insert_flows(enriched, monitor_type="active") |
| Status polling | Frontend | GET /api/realtime/status every 2s (when running) → capture_count, last_flow_count, flow_counts, capture_error |
| Dashboard Active tab | Dashboard.jsx | GET /api/dashboard/stats?monitor_type=active → same KPIs/charts as passive but only active flows |

---

## 12. Important implementation details

- **No test/synthetic flows:** Only real packets are turned into flows and stored. There is no “inject test flows” endpoint or button.
- **Default interface = loopback:** Empty/default selection uses `lo` so that local API traffic (e.g. frontend calling backend on the same machine) is captured without needing a specific NIC.
- **Interface list from Scapy:** The dropdown is populated from Scapy’s `get_if_list()` so only capture-capable interfaces are offered, reducing “interface not found” errors.
- **Capture errors visible:** `_last_capture_error` is surfaced in status so the UI can show “Operation not permitted” or similar and remind the user to run with sudo.
- **Single monitor instance:** One global `realtime_monitor`; only one capture can run at a time. Start when already running returns an error response.
- **Daemon thread:** The capture loop runs in a daemon thread, so it does not prevent process exit; no graceful shutdown of the capture loop (stop just sets `running = False`).

This is the full picture of how live (active) monitoring is currently implemented end to end.
