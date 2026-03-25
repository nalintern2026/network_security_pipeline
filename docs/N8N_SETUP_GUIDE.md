# n8n Workflow Automation — Setup & Viewing Guide

This guide shows how to install, run, and view the NetGuard n8n automation workflows.

---

## Quick Start (Docker — Recommended)

Everything runs with one command since n8n is already added to `docker-compose.yml`.

```bash
cd nal
docker compose up -d
```

That starts three services:

| Service | URL | What it is |
|---------|-----|-----------|
| Backend | http://localhost:8000 | FastAPI + ML engine |
| Frontend | http://localhost:5173 | React dashboard |
| **n8n** | **http://localhost:5678** | **Workflow automation UI** |

Open **http://localhost:5678** in your browser to view n8n.

---

## Step-by-Step Setup

### 1. Start the stack

```bash
cd /home/ictd/Desktop/Network/nal
docker compose up -d
```

Verify all three containers are running:

```bash
docker compose ps
```

You should see `backend`, `frontend`, and `n8n` all with status `Up`.

### 2. First-time n8n setup

Open http://localhost:5678 in your browser.

On first launch, n8n asks you to create an owner account:
- Enter any email and password (this is local-only)
- Click **Set up**
- Skip the optional survey

You're now in the n8n dashboard.

### 3. Import the workflows

**Option A — Automatic (script)**

```bash
cd /home/ictd/Desktop/Network/nal/n8n

# If n8n has no API auth (first-time local setup):
bash import_workflows.sh

# If n8n requires an API key:
# Go to n8n → Settings → API → Create API Key, then:
N8N_API_KEY=your_key_here bash import_workflows.sh
```

**Option B — Manual (drag and drop)**

1. In n8n, click **Add Workflow** (top right)
2. In the new workflow editor, click the **three-dot menu** (⋯) at top → **Import from File**
3. Select a JSON file from `nal/n8n/`:
   - `1_network_security_monitoring.json`
   - `2_automated_file_analysis.json`
   - `3_training_pipeline.json`
   - `4_daily_security_report.json`
   - `5_live_monitoring_management.json`
4. Repeat for each workflow

### 4. Configure environment variables

In n8n: **Settings** (gear icon bottom-left) → **Variables** (or set via docker-compose env):

| Variable | Set to | Purpose |
|----------|--------|---------|
| `NETGUARD_API_URL` | `http://backend:8000` (Docker) or `http://localhost:8000` (local) | Backend API URL |
| `ALERT_WEBHOOK_URL` | Your Slack/Teams/Discord webhook URL | Where alerts are sent |

These are pre-configured in `docker-compose.yml`. You only need to change `ALERT_WEBHOOK_URL` to a real webhook if you want notifications.

### 5. Activate a workflow

1. Open any imported workflow
2. Click the **toggle switch** in the top-right corner to set it to **Active**
3. The workflow is now running on its schedule

### 6. Test a workflow manually

1. Open any workflow
2. Click **Execute Workflow** (play button) to run it once immediately
3. Watch the execution — each node turns green (success) or red (error)
4. Click any node to see its input/output data

---

## Running n8n Without Docker

If you prefer to run n8n standalone:

### Install n8n

```bash
# Option 1: npm (requires Node.js 18+)
npm install -g n8n

# Option 2: npx (no install needed)
npx n8n start
```

### Run it

```bash
# Set the backend URL (when running locally, not Docker)
export NETGUARD_API_URL=http://localhost:8000
export ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

n8n start
```

Open http://localhost:5678 and import the workflows from `nal/n8n/`.

### Run alongside the backend

Terminal 1 — Backend:
```bash
cd /home/ictd/Desktop/Network/nal/backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Terminal 2 — Frontend:
```bash
cd /home/ictd/Desktop/Network/nal/frontend
npm run dev
```

Terminal 3 — n8n:
```bash
export NETGUARD_API_URL=http://localhost:8000
n8n start
```

---

## Viewing & Using the Workflows

### n8n Dashboard (http://localhost:5678)

After importing, you'll see all 5 workflows listed:

```
┌──────────────────────────────────────────────────────────────────┐
│  Workflows                                            + Add      │
│──────────────────────────────────────────────────────────────────│
│  ● NetGuard - Security Monitoring & Alerting     [Active ○───●] │
│  ● NetGuard - Automated File Analysis            [Active ○───●] │
│  ● NetGuard - Training Pipeline Automation       [Active ○───●] │
│  ● NetGuard - Daily Security Report              [Active ○───●] │
│  ● NetGuard - Live Monitoring Management         [Active ○───●] │
└──────────────────────────────────────────────────────────────────┘
```

Click any workflow to open the **visual editor** — you'll see the node graph:

### How to inspect and debug nodes

1. **Run the whole workflow** — Click **Test workflow** at the bottom (or use the **Execute workflow** play button). Always start from the trigger so every upstream node runs in order. If you run only one node from the middle, earlier nodes may show as “not executed” and Code nodes that reference them will fail.

2. **See input/output for one node** — After a run, **click a node**. The right panel shows **INPUT** (what entered the node) and **OUTPUT** (what it produced). Use the tabs or arrows to switch between items if there are several.

3. **Execution history** — Open the **Executions** list (clock icon in the left sidebar, or **Workflows → Executions**). Click a past run to open the **execution detail** view; click each node in the diagram to see its data for that run.

4. **Pinned data** — Right-click a node → **Pin data** to save sample output for testing without calling the API again (useful when building).

5. **Workflow 1 wiring** — The chain must be **Get Dashboard Stats → Get Critical Anomalies → Analyze Threats** only. If you still see a line from **Get Dashboard Stats** straight to **Analyze Threats**, delete that connection and re-import `1_network_security_monitoring.json` so **Analyze Threats** receives input only from **Get Critical Anomalies**.

### Workflow 1: Security Monitoring & Alerting

```
[Every 5 Min] → [Health Check] → [Is Healthy?]
                                      │
                            YES ──────┼──────── NO
                            │                    │
                    [Get Stats + Anomalies]   [API Down Alert]
                            │
                    [Analyze Threats]
                            │
                    [Alerts?] ──YES── [Format] → [Send Webhook]
                            │
                            └──NO── [All Clear]
```

### Workflow 2: Automated File Analysis

```
[Webhook POST] ──or── [Every 10 Min Scan]
        │                      │
        └──────────┬───────────┘
                   │
           [Upload to API]
                   │
           [Evaluate Results]
                   │
           [Threats?] ──YES── [Alert]
```

### Workflow 3: Training Pipeline

```
[Weekly Mon 2AM] ──or── [Webhook POST]
        │
[Get Current Metrics] → [Check Data] → [Run train.py]
                                             │
                                    [Compare Before/After]
                                             │
                                    [Send Training Report]
```

### Workflow 4: Daily Security Report

```
[Daily 8AM]
     │
     ├── [Dashboard Stats]
     ├── [Passive Stats]        All 7 calls
     ├── [Active Stats]         run in
     ├── [Anomalies]            parallel
     ├── [Trends]               ─────────→ [Compile Report] → [Send]
     ├── [Model Metrics]                         │
     └── [History]                    [Critical?] → [Urgent Alert]
```

### Workflow 5: Live Monitoring Management

```
[Webhook POST]                 [Every 2 Min Poll]
  action=start/stop/               │
  status/interfaces          [Check Monitor Health]
        │                          │
  [Route] → [API Call]      [Needs Restart?] → [Auto-Restart]
        │                          │
  [Respond]                  [Send Alert if needed]
```

---

## Execution History

n8n keeps a log of every workflow run. View it:

1. Click a workflow name
2. Click **Executions** tab (clock icon in the sidebar)
3. See the list of past runs with status (Success / Error)
4. Click any execution to see the data that flowed through each node

---

## Webhook URLs (for Workflow 2 & 5)

After activating workflows with webhook triggers, n8n provides URLs:

| Workflow | Webhook Path | How to call |
|----------|-------------|-------------|
| File Analysis | `/webhook/netguard-analyze` | `curl -X POST http://localhost:5678/webhook/netguard-analyze -H 'Content-Type: application/json' -d '{"file_path":"/path/to/file.pcap"}'` |
| Training Trigger | `/webhook/netguard-train` | `curl -X POST http://localhost:5678/webhook/netguard-train` |
| Monitor Control | `/webhook/netguard-monitor` | `curl -X POST http://localhost:5678/webhook/netguard-monitor -H 'Content-Type: application/json' -d '{"action":"start","interface":"eth0"}'` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| n8n container won't start | Run `docker compose logs n8n` to check errors |
| "Connection refused" in workflows | Check `NETGUARD_API_URL` — inside Docker use `http://backend:8000`, locally use `http://localhost:8000` |
| Webhook returns 404 | Make sure the workflow is **Active** (toggle on) |
| Import script fails with auth error | Create an API key in n8n Settings → API, then set `N8N_API_KEY` |
| n8n can't reach backend | Ensure both are on the same Docker network (`docker compose up` handles this) |
| Workflows show "inactive" | Click each workflow → toggle Active in the top-right |
| Email/Slack not working | Replace the webhook HTTP nodes with n8n's built-in Email or Slack nodes and add credentials |

---

## File Locations

```
nal/
├── n8n/
│   ├── 1_network_security_monitoring.json    ← Every 5 min health + threat check
│   ├── 2_automated_file_analysis.json        ← Auto-upload PCAP/CSV files
│   ├── 3_training_pipeline.json              ← Weekly ML model retraining
│   ├── 4_daily_security_report.json          ← Daily aggregated report
│   ├── 5_live_monitoring_management.json     ← Live capture control + auto-restart
│   ├── import_workflows.sh                   ← Auto-import script
│   └── README.md                             ← Detailed technical docs
├── docker-compose.yml                        ← Updated with n8n service
└── docs/
    └── N8N_SETUP_GUIDE.md                    ← This file
```
