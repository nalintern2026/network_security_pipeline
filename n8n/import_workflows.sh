#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# NetGuard n8n Workflow Importer
# Imports all workflow JSON files into a running n8n instance via API.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

N8N_URL="${N8N_URL:-http://localhost:5678}"
N8N_API_KEY="${N8N_API_KEY:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   NetGuard n8n Workflow Importer              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Wait for n8n to be ready ──────────────────────────────────────────
echo -e "${YELLOW}Waiting for n8n at ${N8N_URL} ...${NC}"
MAX_WAIT=60
WAITED=0
until curl -sf "${N8N_URL}/healthz" >/dev/null 2>&1 || curl -sf "${N8N_URL}/" >/dev/null 2>&1; do
  sleep 2
  WAITED=$((WAITED + 2))
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo -e "${RED}n8n not reachable after ${MAX_WAIT}s. Is it running?${NC}"
    echo "  Try:  docker compose up -d n8n"
    echo "  Or:   npx n8n start"
    exit 1
  fi
done
echo -e "${GREEN}n8n is ready.${NC}"
echo ""

# ── Build auth header ─────────────────────────────────────────────────
AUTH_HEADER=""
if [ -n "$N8N_API_KEY" ]; then
  AUTH_HEADER="-H \"X-N8N-API-KEY: ${N8N_API_KEY}\""
  echo -e "${GREEN}Using API key authentication.${NC}"
else
  echo -e "${YELLOW}No N8N_API_KEY set — using unauthenticated import.${NC}"
  echo -e "${YELLOW}If n8n requires auth, set N8N_API_KEY env var first.${NC}"
fi
echo ""

# ── Import each workflow ──────────────────────────────────────────────
IMPORTED=0
FAILED=0

for wf_file in "$SCRIPT_DIR"/[0-9]_*.json; do
  [ -f "$wf_file" ] || continue
  WF_NAME=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['name'])" "$wf_file" 2>/dev/null || basename "$wf_file" .json)

  echo -ne "  Importing: ${CYAN}${WF_NAME}${NC} ... "

  RESPONSE=$(curl -sf -X POST "${N8N_URL}/api/v1/workflows" \
    -H "Content-Type: application/json" \
    ${AUTH_HEADER} \
    -d @"$wf_file" 2>&1) && RC=$? || RC=$?

  if [ $RC -eq 0 ]; then
    WF_ID=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id','?'))" 2>/dev/null || echo "?")
    echo -e "${GREEN}OK${NC} (id: ${WF_ID})"
    IMPORTED=$((IMPORTED + 1))
  else
    echo -e "${RED}FAILED${NC}"
    echo "    Response: $(echo "$RESPONSE" | head -c 200)"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo -e "${CYAN}──────────────────────────────────────────────${NC}"
echo -e "  Imported: ${GREEN}${IMPORTED}${NC}   Failed: ${RED}${FAILED}${NC}"
echo ""

if [ "$IMPORTED" -gt 0 ]; then
  echo -e "${GREEN}Open n8n to view and activate workflows:${NC}"
  echo -e "  ${CYAN}${N8N_URL}${NC}"
  echo ""
  echo -e "${YELLOW}Next steps:${NC}"
  echo "  1. Open each workflow in the n8n editor"
  echo "  2. Set your ALERT_WEBHOOK_URL (Slack/Teams/Discord webhook)"
  echo "  3. Toggle the workflow to Active (top-right switch)"
  echo "  4. Test with 'Execute Workflow' button"
fi

if [ "$FAILED" -gt 0 ] && [ "$IMPORTED" -eq 0 ]; then
  echo -e "${YELLOW}Tip: If n8n requires authentication:${NC}"
  echo "  1. Go to ${N8N_URL} → Settings → API → Create API Key"
  echo "  2. Re-run:  N8N_API_KEY=your_key_here bash $0"
  echo ""
  echo -e "${YELLOW}Alternative: Manual import${NC}"
  echo "  1. Open ${N8N_URL}"
  echo "  2. Click 'Add Workflow' → '...' menu → 'Import from File'"
  echo "  3. Select each .json file from: ${SCRIPT_DIR}/"
fi
