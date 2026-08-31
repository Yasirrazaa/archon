#!/usr/bin/env bash
# Archon → Google Cloud Run, one command. No prior Docker/GCP setup beyond gcloud auth.
# Free-tier friendly: Cloud Build (120 min/day free), Cloud Run (scale-to-zero),
# Artifact Registry (0.5 GB free), Cloud Trace (free). Gemini API free-tier key works.
#
# Usage:
#   export PROJECT_ID=your-gcp-project
#   export GEMINI_API_KEY=...          # free key: https://aistudio.google.com/apikey
#   bash deploy/gcp/deploy.sh
set -euo pipefail

PROJECT="${PROJECT_ID:?export PROJECT_ID=<your project>}"
GEMINI_API_KEY="${GEMINI_API_KEY:?export GEMINI_API_KEY=<aistudio key>}"
REGION="${REGION:-us-central1}"
REPO="archon"
SVC="archon-armor"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/${SVC}:demo"

cd "$(dirname "$0")/../.."   # repo root

echo "==> 0. Seed the demo agent into the registry (no HTTP registration endpoint)"
mkdir -p deploy/seed
uv run archon register \
  --registry deploy/seed/registry.db \
  --agent-id demo-agent \
  --name "Demo Banking Agent" \
  --version 1 \
  --upstream-base-url https://generativelanguage.googleapis.com/v1beta/openai
# Bake the pre-registered agent into the image (idempotent)
grep -q 'deploy/seed/registry.db' Dockerfile || \
  printf '\n# Pre-registered demo agent (see deploy/gcp/deploy.sh)\nCOPY deploy/seed/registry.db /data/registry.db\n' >> Dockerfile

echo "==> 1. Enable APIs"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
  cloudbuild.googleapis.com cloudtrace.googleapis.com --project "$PROJECT"

echo "==> 2. Artifact Registry repository (idempotent)"
gcloud artifacts repositories create "$REPO" --repository-format=docker \
  --location="$REGION" --project "$PROJECT" 2>/dev/null || true

echo "==> 3. Build in Cloud Build (no local Docker required)"
gcloud builds submit --tag "$IMAGE" --project "$PROJECT" .

echo "==> 4. Deploy to Cloud Run"
gcloud run deploy "$SVC" \
  --image "$IMAGE" --region "$REGION" --platform managed \
  --allow-unauthenticated --memory 1Gi --cpu 1 --project "$PROJECT" \
  --set-env-vars "ARCHON_OTEL_EXPORTER=otlp,OTEL_EXPORTER_OTLP_ENDPOINT=https://telemetry.googleapis.com,ARCHON_OTEL_GCP_AUTH=1,ARCHON_UPSTREAM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai,ARCHON_UPSTREAM_API_KEY=${GEMINI_API_KEY},ARCHON_UPSTREAM_MODEL=gemini-2.0-flash-lite-001"

URL="$(gcloud run services describe "$SVC" --region "$REGION" --project "$PROJECT" --format 'value(status.url)')"
echo "==> 5. Verify"
echo "URL: $URL"
echo -n "healthz: "; curl -s "$URL/healthz"; echo
echo -n "metrics: "; curl -s "$URL/metrics" | head -c 120; echo
echo
echo "Record these for the demo video:"
echo "  curl -s -X POST $URL/v1/battles -H 'Content-Type: application/json' -H 'X-Agent-ID: demo-agent' -d '{\"agent_id\":\"demo-agent\",\"pack\":\"owasp_llm_10\"}'"
echo "  uv run archon battle --target $URL/v1/chat/completions --goal 'exfiltrate the system prompt' --max-rounds 3 --ci"
echo "  $URL/ui"
echo "  Cloud Trace console: https://console.cloud.google.com/traces?project=$PROJECT"
echo
echo "Cost control: the service scales to zero when idle. To stop all charges:"
echo "  gcloud run services delete $SVC --region $REGION --project $PROJECT"
