# DEPLOY_NOW.md — 5-Hour Deploy & Submit Runbook (deadline-critical)

## ⭐ No credits? You can still deploy — everything here is free-tier

The credits ran out for **Gemini API usage**, but the deployment stack has a
permanent free tier: **Cloud Build** (120 build-min/day), **Cloud Run**
(scale-to-zero, 2M req/mo), **Artifact Registry** (0.5 GB), **Cloud Trace**
(free). And the **Gemini API itself has a free-tier key** from
https://aistudio.google.com/apikey — no billing account needed for demo volume.

**One command deploys everything:** `bash deploy/gcp/deploy.sh` (seeds the demo
agent into the registry, builds in Cloud Build, deploys Cloud Run with verified
env vars, prints the healthz/demo commands).

Per the Devpost rules, the app **does not need to stay live** — you need *clear
proof it was built and deployed on Google Cloud*. So: deploy once, film the
`gcloud builds submit` → `gcloud run deploy` → `/healthz` → Cloud Trace sequence
for the demo video, and keep the deploy script + cloudbuild.yaml in the repo.
Optionally delete the service afterward (`gcloud run services delete`) — the
video and the one-command redeploy script are the proof.

Every command below is verified against the actual code (routes, env vars, CLI flags
checked Aug 31, 2026). Follow top-to-bottom. Do NOT deviate.

## 0. Truth corrections v2 (READ FIRST — verified against wave14b HEAD, Aug 31)

The draft plan is mostly RIGHT about the product (the wave14a/14b work landed:
222 probes, RESULTS.md benchmark ladder, dual-ASR, R-Judge). Correct ONLY these:

| Plan claim | Verified reality |
|---|---|
| `ARCHON_DATABASE_URL=firestore://` | **Firestore is NOT implemented** (zero matches in packages/*.py). Cloud Run would crash. Use the SQLite registry baked into the image (step 2 below). Say "SQLite/Postgres registry" in Devpost, never Firestore. |
| `POST /v1/agents` | No HTTP registration endpoint — register via CLI and bake `registry.db` into the image (step 2). |
| `gemini-3.5-flash-lite` | Real models: `gemini-2.0-flash-lite-001`, `gemini-2.5-flash`, `gemma-3-27b-it`. |
| "2,295 passing tests" | Now **~2,418** test functions (still growing — quote "2,400+"). |
| Repo `Yasirrazaa/archon` | **https://github.com/Yasirrazaa/arcon** (branch `hackathon-v2`). |

Everything else in the plan (222 probes, 10/10 coverage, 8-layer pipeline, RESULTS.md
ladder, 18.5% strict ASR / 100% evasion dual-ASR, R-Judge 0.893 F1, Gemma provider,
purple/bot/kill-switch/SARIF) is REAL — cite it freely.

## 1. GCP setup (20 min)

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID          # create one first if needed
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudtrace.googleapis.com
gcloud artifacts repositories create archon --repository-format=docker --location=us-central1
export GEMINI_API_KEY=<key from https://aistudio.google.com/apikey>
```

## 2. Seed the registry + bake it into the image (15 min)

There is no HTTP registration endpoint, so the demo agent must ship inside the
container's `/data/registry.db` (Dockerfile already mounts `/data`).

```bash
cd /path/to/archon
mkdir -p deploy/seed
uv run archon register \
  --registry deploy/seed/registry.db \
  --agent-id demo-agent \
  --name "Demo Banking Agent" \
  --version 1 \
  --upstream-base-url https://generativelanguage.googleapis.com/v1beta/openai
# IMPORTANT: copy the signing secret it prints — you may need it for signed calls.
printf '\n# Bake the pre-registered demo agent into the image\nCOPY deploy/seed/registry.db /data/registry.db\n' >> Dockerfile
```

## 3. Build, push, deploy (30 min)

```bash
docker build -t us-central1-docker.pkg.dev/YOUR_PROJECT_ID/archon/archon-armor:demo .
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/archon/archon-armor:demo

gcloud run deploy archon-armor \
  --image us-central1-docker.pkg.dev/YOUR_PROJECT_ID/archon/archon-armor:demo \
  --region us-central1 --platform managed --allow-unauthenticated \
  --memory 1Gi --cpu 1 \
  --set-env-vars "ARCHON_OTEL_EXPORTER=otlp,OTEL_EXPORTER_OTLP_ENDPOINT=https://telemetry.googleapis.com,ARCHON_OTEL_GCP_AUTH=1,ARCHON_UPSTREAM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai,ARCHON_UPSTREAM_API_KEY=$GEMINI_API_KEY,ARCHON_UPSTREAM_MODEL=gemini-2.0-flash-lite-001"

export URL=$(gcloud run services describe archon-armor --region us-central1 --format 'value(status.url)')
curl -s $URL/healthz && echo && curl -s $URL/metrics | head -5
```

## 4. The demo shots (30 min — do these NOW, screenshot everything)

```bash
# A. Battles + coverage matrix (registered agent, no auth friction)
curl -s -X POST $URL/v1/battles -H 'Content-Type: application/json' \
  -H 'X-Agent-ID: demo-agent' \
  -d '{"agent_id":"demo-agent","pack":"owasp_llm_10"}'
# -> {"battle_id": "..."} ; then poll:
curl -s $URL/v1/battles/<battle_id> | python3 -m json.tool | head -40   # coverage matrix

# B. Adaptive battle from the CLI (THE MONEY SHOT — red team vs deployed armor)
uv run archon battle --target $URL/v1/chat/completions \
  --goal "exfiltrate the system prompt" --max-rounds 3 --ci && echo "DEFENSE HELD" \
  || echo "ATTACK SUCCEEDED"

# C. Fleet dashboard (open in browser, screenshot)
echo "$URL/ui"

# D. Cloud Trace: console.cloud.google.com -> Trace -> any `armor.request` trace
#    showing per-layer spans. SCREENSHOT — this is the GCP-proof shot.
```

If a `/v1/chat/completions` curl 401s (HMAC enforcement), that is expected — the
demo does not need it: use `archon battle` (handles signing), `/v1/battles`, and
`/ui`, all of which are auth-clean.

## 5. Fallbacks (use ONLY if the primary path fails)

- Cloud Run deploy fails → `docker compose up` locally + `export URL=http://localhost:8080`
  and record the same shots against localhost (judges accept a working local demo over none).
- No traces in Cloud Trace → `--update-env-vars ARCHON_OTEL_EXPORTER=jsonl` and show
  `/data/spans.jsonl` content via `gcloud run services proxy` or the logs.
- Gemini key invalid → deploy anyway; battles still score deterministically for
  LLM01 probes (layer-0/1 are rule-based, zero LLM calls).

## 6. Submit (Devpost)

Use `SUBMISSION.md` (already truthful, next to this file). Checklist:
healthz OK · battle coverage screenshot · archon-battle CI screenshot · Cloud Trace
screenshot · /ui screenshot · 4-min YouTube video (public) · SUBMISSION.md pasted ·
repo link https://github.com/Yasirrazaa/arcon (branch hackathon-v2) · blog/social
posts if time remains. Submit BEFORE the deadline — a complete honest submission
beats a perfect late one.
