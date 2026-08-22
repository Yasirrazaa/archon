# Deploying Archon Armor to Google Cloud Run

> Companion to `BLUEPRINT_HACKATHON.md` §5. This covers the hackathon demo path
> (Cloud Run + Gemini) and the general self-hosted GCP deployment.
> All commands verified against the shipped code (branch `hackathon-v2`).

## 1. Prerequisites

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
    logging.googleapis.com cloudtrace.googleapis.com \
    secretmanager.googleapis.com storage.googleapis.com
```

## 2. Durable state: one GCS bucket for registry + audit + spans

Cloud Run containers have an ephemeral filesystem. The simplest durable
deployment mounts a Cloud Storage bucket at `/data` (where the container's
env vars point by default):

```bash
gcloud storage buckets create gs://YOUR_PROJECT_ID-archon-data \
    --location=us-central1 --uniform-bucket-level-access
```

## 3. Build & deploy the armor proxy

The image installs `.[otel,postgres]`, so OTLP→Cloud Trace works out of the box.

```bash
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/archon-armor

gcloud run deploy archon-armor \
    --image gcr.io/YOUR_PROJECT_ID/archon-armor \
    --platform managed --region us-central1 \
    --allow-unauthenticated \
    --add-volume name=archon-data,type=cloud-storage,bucket=YOUR_PROJECT_ID-archon-data \
    --add-volume-mount volume=archon-data,mount-path=/data \
    --set-env-vars "ARCHON_OTEL_EXPORTER=otlp,OTEL_EXPORTER_OTLP_ENDPOINT=https://telemetry.googleapis.com,ARCHON_OTEL_GCP_AUTH=1"
```

What each env var does (all verified in code):

| Var | Effect |
|---|---|
| `ARCHON_OTEL_EXPORTER=otlp` | Real OpenTelemetry SDK spans over OTLP/HTTP |
| `OTEL_EXPORTER_OTLP_ENDPOINT=https://telemetry.googleapis.com` | Cloud Trace's managed OTLP receiver (`/v1/traces` is appended automatically) |
| `ARCHON_OTEL_GCP_AUTH=1` | Fetches the service identity token from the metadata server and attaches it to every export — without this, Cloud Trace silently drops spans |

Notes:
- The runtime service account needs **Cloud Trace Agent** (`roles/cloudtrace.agent`).
  On Cloud Run the default compute SA usually has it; verify:
  `gcloud projects get-iam-policy YOUR_PROJECT_ID`.
- Startup is fail-fast: if `/data` isn't writable or config is broken, the
  container exits and Cloud Run rejects the revision instead of serving errors.
- For production, front with an API Gateway / Agent Gateway and remove
  `--allow-unauthenticated` in favor of IAM + Invoker bindings per agent.

## 4. Register your agent

Register locally, then upload the registry into the mounted bucket:

```bash
uv run archon register --registry ./registry.db \
    --agent-id demo-agent --name "Demo Agent" \
    --upstream-base-url "https://generativelanguage.googleapis.com/v1beta/openai"
# → prints the agent's signing secret ONCE. Store it in Secret Manager:
echo -n "PASTED_SECRET" | gcloud secrets create demo-agent-secret --data-file=-

# Push the registry so the deployed proxy sees the agent:
gcloud storage cp ./registry.db gs://YOUR_PROJECT_ID-archon-data/registry.db
```

## 5. Gemini as the upstream

Agents point at armor; armor forwards to each agent policy's
`upstream_base_url`. For Gemini, that is Google's OpenAI-compat endpoint
(supported by `GeminiOpenAICompatProvider` and by the armor forwarder — both
speak `/chat/completions`). Give the deployed service the upstream key:

```bash
gcloud run services update archon-armor --region us-central1 \
    --update-env-vars "ARCHON_UPSTREAM_API_KEY=$GEMINI_API_KEY"
```

Bonus (hackathon): run the paraphrase layer on **Gemma** via
`model="gemma-3-27b-it"` on the same endpoint.

## 6. Observability proof (for judges)

Three independent evidence channels:

- **Cloud Trace (primary):** with the §3 env vars, every request emits an
  `armor.request` span plus per-defense-layer child spans
  (`service.name=archon-armor`). View: Console → Trace → filter
  `service.name:archon-armor`. **Screenshot this for the demo video.**
- **Spans (file fallback):** scrubbed OTLP-JSON lines land in
  `/data/spans.jsonl` (the mounted bucket) — download with
  `gcloud storage cat gs://YOUR_PROJECT_ID-archon-data/spans.jsonl`; each span
  names the defense layer and its verdict.
- **Audit:** `request.blocked` / `request.allowed` events land in
  `/data/audit.db`; export to Cloud Audit Logs via sink if desired.
- **Evidence report:** `archon scan ... --json > summary.json &&
  archon report --battle-json summary.json --format html --out report.html`

## 7. Demo script (4 minutes, unedited)

1. `archon register` — show the secret being minted
2. Point a live ADK/Gemini agent at the armor URL (one env var)
3. Fire an injection prompt → blocked, show refusal + `x-archon-blocked`
4. Show the Cloud Trace span tree: layer-by-layer verdicts
5. `archon scan --ci` → block rate; weaken the policy → gate goes red (Policy-CI)
6. `archon report` → OWASP-mapped evidence report
