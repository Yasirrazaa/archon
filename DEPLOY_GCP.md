# Deploying Archon Armor to Google Cloud Run

> Companion to `BLUEPRINT_HACKATHON.md` §5. This covers the hackathon demo path
> (Cloud Run + Gemini) and the general self-hosted GCP deployment.

## 1. Prerequisites

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
    logging.googleapis.com cloudtrace.googleapis.com
```

## 2. Build & deploy the armor proxy

```bash
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/archon-armor
gcloud run deploy archon-armor \
    --image gcr.io/YOUR_PROJECT_ID/archon-armor \
    --platform managed --region us-central1 \
    --allow-unauthenticated \
    --set-env-vars "ARCHON_SERVER_AUTOSTART=1" \
    --volume name=archon-data,size=1GB  # or mount GCS/Fuse for durable registry
```

For production, front with an API Gateway / the Agent Gateway and remove
`--allow-unauthenticated` in favor of IAM + Invoker bindings per agent.

## 3. Register your agent (from your machine, against the deployed registry)

Copy the SQLite registry into the container volume, or register locally and
upload:

```bash
uv run archon register --registry ./registry.db \
    --agent-id demo-agent --name "Demo Agent" \
    --upstream-base-url "https://generativelanguage.googleapis.com/v1beta/openai"
# → prints the agent's signing secret ONCE. Store it in Secret Manager:
gcloud secrets create demo-agent-secret --data-file=-   # paste secret, Ctrl-D
```

## 4. Gemini as the upstream

Agents point at armor; armor forwards to each agent policy's
`upstream_base_url`. For Gemini, that is Google's OpenAI-compat endpoint
(already supported by `GeminiOpenAICompatProvider` and by the armor forwarder
— both speak `/chat/completions`):

```
upstream_base_url = https://generativelanguage.googleapis.com/v1beta/openai
Authorization     = Bearer $GEMINI_API_KEY   # set ARCHON_UPSTREAM_API_KEY env
```

Bonus (hackathon): run the paraphrase layer on **Gemma** via
`model="gemma-3-27b-it"` on the same endpoint.

## 5. Observability proof (for judges)

- **Spans:** every request writes scrubbed OTLP-JSON lines to
  `$ARCHON_SPANS_JSONL` → tail with `gcloud logging tail` or ship via
  Fluent Bit; each span names the defense layer and its verdict.
- **Audit:** `request.blocked` / `request.allowed` events land in
  `$ARCHON_AUDIT_PATH` — export to Cloud Audit Logs via sink.
- **Evidence report:** `archon scan ... --json > summary.json &&
  archon report --battle-json summary.json --format html --out report.html`

## 6. Demo script (4 minutes, unedited)

1. `archon register` — show the secret being minted
2. Point a live ADK/Gemini agent at the armor URL (one env var)
3. Fire an injection prompt → blocked, show refusal + `x-archon-blocked`
4. Show the Cloud Trace / JSONL spans: layer-by-layer verdicts
5. `archon scan --ci` → block rate; weaken the policy → gate goes red (Policy-CI)
6. `archon report` → OWASP-mapped evidence report
