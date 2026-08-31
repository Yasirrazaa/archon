#!/usr/bin/env bash
# Cloud Shell demo (NO billing account required).
# Builds and serves archon-armor inside a Google Cloud Shell VM — real Google
# Cloud infrastructure, zero card. Cloud Run activation (one command, in
# deploy/gcp/deploy.sh) additionally requires billing; this script is the
# no-card proof path.
#
# Usage: paste this entire file's URL into Cloud Shell, or:
#   bash deploy/gcp/cloudshell-demo.sh
set -euo pipefail

PORT=8080
echo "==> Environment proof (this IS a Google Cloud VM)"
gcloud config list --format 'value(core.project)' | sed 's/^/project: /'
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/zone" \
  | sed 's/^/zone: /' || echo "zone: (metadata unavailable)"

echo "==> 1. Seed the demo agent into the registry"
mkdir -p deploy/seed
uv run archon register \
  --registry deploy/seed/registry.db \
  --agent-id demo-agent --name "Demo Banking Agent" --version 1 \
  --upstream-base-url https://generativelanguage.googleapis.com/v1beta/openai
grep -q 'deploy/seed/registry.db' Dockerfile || \
  printf '\nCOPY deploy/seed/registry.db /data/registry.db\n' >> Dockerfile

echo "==> 2. Build the image (docker is preinstalled in Cloud Shell)"
docker build -t archon-armor:demo .

echo "==> 3. Run it (pass GEMINI_API_KEY for live LLM layers; optional)"
docker run -d --name archon-armor -p ${PORT}:8080 \
  -e ARCHON_UPSTREAM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai \
  -e ARCHON_UPSTREAM_API_KEY="${GEMINI_API_KEY:-}" \
  -e ARCHON_UPSTREAM_MODEL=gemini-2.0-flash-lite-001 \
  -e ARCHON_OTEL_EXPORTER=jsonl \
  archon-armor:demo
sleep 3

echo "==> 4. Verify"
echo -n "healthz: "; curl -s "http://localhost:${PORT}/healthz"; echo
echo -n "metrics: "; curl -s "http://localhost:${PORT}/metrics" | head -c 120; echo

echo "==> 5. Demo shots (film these)"
echo "  a) Web Preview: Cloud Shell top-right 'Web Preview' -> 'Preview on port 8080' -> /ui dashboard"
echo "  b) curl -s -X POST http://localhost:${PORT}/v1/battles -H 'Content-Type: application/json' -H 'X-Agent-ID: demo-agent' -d '{\"agent_id\":\"demo-agent\",\"pack\":\"owasp_llm_10\"}'"
echo "  c) docker logs archon-armor | tail -5   (per-layer verdicts / span JSONL)"
echo
echo "==> Cloud Run (when billing is available) is ONE command: bash deploy/gcp/deploy.sh"
