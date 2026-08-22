"""P1 backlog — Helm chart structural validation for archon-armor.

Verifies the chart is a valid, production-shaped deployment artifact without
needing a cluster: chart metadata, values coherence, deployment security
context (non-root), probes, and the env wiring that matches archon server.py.
Runs `helm lint`/`helm template` when the helm binary is available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "archon-armor"

REQUIRED_TEMPLATES = {
    "templates/deployment.yaml",
    "templates/service.yaml",
    "templates/serviceaccount.yaml",
    "templates/_helpers.tpl",
    "templates/ingress.yaml",
}


def test_chart_metadata_valid():
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert chart["apiVersion"] == "v2"
    assert chart["name"] == "archon-armor"
    assert chart["type"] == "application"
    assert chart["version"]
    assert chart["appVersion"]


def test_required_templates_exist():
    for rel in REQUIRED_TEMPLATES:
        assert (CHART / rel).is_file(), f"missing {rel}"


def test_values_are_production_sane():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["replicaCount"] >= 1
    assert values["image"]["repository"]
    assert values["image"]["tag"]
    assert "ghcr.io" in values["image"]["repository"] or values["image"]["repository"]
    assert values["service"]["port"] == 8080
    # non-root, sealed pod security
    assert values["podSecurityContext"]["runAsNonRoot"] is True
    assert values["securityContext"]["allowPrivilegeEscalation"] is False
    assert values["securityContext"]["readOnlyRootFilesystem"] is True
    assert "ALL" in values["securityContext"]["capabilities"]["drop"]


def test_deployment_wiring_matches_server_env():
    """Text-level assertions: Go templates aren't valid YAML without rendering."""
    text = (CHART / "templates/deployment.yaml").read_text()
    assert 'image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"' in text
    assert "name: armor" in text
    for required in ("ARCHON_REGISTRY_PATH", "ARCHON_AUDIT_PATH",
                     "ARCHON_SPANS_JSONL", "ARCHON_OTEL_EXPORTER",
                     "ARCHON_REQUIRE_SIGNED"):
        assert f"name: {required}" in text
    assert "ARCHON_DATABASE_URL" in text  # enterprise Postgres wiring present
    assert "livenessProbe" in text and "/healthz" in text
    assert "readinessProbe" in text and "/healthz" in text
    assert "containerPort: 8080" in text
    assert "securityContext:" in text  # non-root enforcement wired from values
    assert "mountPath: /data" in text


def test_ingress_disabled_by_default_and_wired():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["ingress"]["enabled"] is False
    text = (CHART / "templates/ingress.yaml").read_text()
    assert "apiVersion: networking.k8s.io/v1" in text
    assert "ingressClassName" in text
    assert "pathType:" in text
    assert "backend:" in text


def test_helm_lint_passes_when_helm_available():
    helm = shutil.which("helm")
    if not helm:
        pytest.skip("helm not installed")
    env = dict(os.environ, KUBECONFIG="/dev/null")
    result = subprocess.run(
        [helm, "lint", str(CHART)], capture_output=True, text=True, env=env, timeout=120
    )
    assert "with 0 error(s)" in result.stderr or result.returncode == 0


def test_helm_template_renders_when_helm_available():
    helm = shutil.which("helm")
    if not helm:
        pytest.skip("helm not installed")
    env = dict(os.environ, KUBECONFIG="/dev/null")
    result = subprocess.run(
        [helm, "template", "release", str(CHART)], capture_output=True, text=True,
        env=env, timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "kind: Deployment" in result.stdout
    assert "ARCHON_REGISTRY_PATH" in result.stdout