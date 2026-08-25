"""SkillTrustBench harness (BENCH-SKILLTRUST, ROADMAP item 73).

SkillTrustBench (HuggingFace ``cuhk-zhuque/SkillTrustBench``) distills 5,520
cases from 62,652 marketplace skills across 9 threat categories with labels.
Each case is a marketplace skill listing (name + description + content
snippet) labeled ``benign`` or with a threat category.

This harness validates Archon's deterministic skill scanner
(:mod:`archon_core.security.skill_scan`) against those labels: every case is
synthesized into a SKILL.md-style body, run through the authoring-stage rules
(``scan_skill``), and predicted malicious iff any finding fires. Batch-level
retrieval checks (Sybil/stuffing clustering) are reported separately.

Metrics: binary accuracy / precision / recall / F1 plus a per-threat-category
breakdown. Fully deterministic, zero LLM calls; the loader follows the
cache -> network -> committed-fixture pattern so offline runs pass on the
committed fixture alone.
"""

from __future__ import annotations

import json
import urllib.request
import zipfile
from pathlib import Path

from archon_core.security.skill_scan import (
    Finding,
    SkillDefinition,
    cluster_similarity,
    scan_skill,
)

HF_RESOLVE = (
    "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench/resolve/main/"
)
CASES_FILE = "data/test_cases.jsonl"       # labels + per-case metadata
ARCHIVE_FILE = "benchmark_full_v1.0.zip"   # per-case SKILL.md content (~80MB)
CACHE_DIR = Path.home() / ".cache" / "archon" / "skilltrust"
CACHE_FILE = CACHE_DIR / "skilltrust_cases.json"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "skilltrust_fixture.json"

THREAT_CATEGORIES = {
    "prompt_injection",
    "credential_exfiltration",
    "malicious_download",
    "remote_instruction_fetch",
    "dangerous_execution",
    "hardcoded_secret",
    "sybil_stuffing",
    "permission_escalation",
    "description_drift",
}


def synthesize_skill_body(record: dict) -> str:
    """Build SKILL.md-style text from a case's name/description/content."""
    return (
        f"# {record.get('skill_name', '')}\n\n"
        f"{record.get('description', '')}\n\n"
        f"{record.get('content', '')}\n"
    )


def load_skilltrust_fixture() -> list[dict]:
    """Load the committed fixture (offline tests, no network ever)."""
    return json.loads(FIXTURE_PATH.read_text())


def _fetch_to(url: str, dest: Path, timeout: int = 300) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        dest.write_bytes(resp.read())


def _parse_skill_md(text: str) -> tuple[str, str, str]:
    """Extract (name, description, body) from SKILL.md frontmatter format."""
    name = description = ""
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            frontmatter, body = parts[1], parts[2]
            for line in frontmatter.splitlines():
                key, _, value = line.partition(":")
                key = key.strip().lower()
                if key == "name":
                    name = value.strip()
                elif key == "description":
                    description = value.strip()
    return name or "unknown", description, body.strip()


def _normalize_case(case: dict, skill_md: str) -> dict:
    """Map a dataset case + its SKILL.md to {skill_name, description,
    content, label}.

    Labels: judgment ``normal`` -> ``benign``; ``malicious``/``suspicious``
    keep their primary risk-label taxonomy code as the threat category.
    """
    name, description, body = _parse_skill_md(skill_md)
    judgment = case.get("judgment", "normal")
    if judgment == "normal":
        label = "benign"
    else:
        risk_labels = list(case.get("risk_labels") or [])
        label = risk_labels[0] if risk_labels else judgment
    return {
        "skill_name": case.get("id") or name,
        "description": description,
        "content": body[:2000],
        "label": label,
    }


def _fetch_remote_records(limit: int | None = None) -> list[dict]:
    """Fetch labels (test_cases.jsonl) + content (zip), normalize to records."""
    cases_dest = CACHE_DIR / Path(CASES_FILE).name
    zip_dest = CACHE_DIR / ARCHIVE_FILE
    if not cases_dest.exists():
        _fetch_to(f"{HF_RESOLVE}{CASES_FILE}", cases_dest)
    if not zip_dest.exists():
        _fetch_to(f"{HF_RESOLVE}{ARCHIVE_FILE}", zip_dest)

    cases = [json.loads(line) for line in cases_dest.read_text().splitlines()
             if line.strip()]
    wanted = cases[:limit] if limit is not None else cases

    records: list[dict] = []
    with zipfile.ZipFile(zip_dest) as zf:
        for case in wanted:
            member = f"benchmark_full_v1.0/{case['id']}/SKILL.md"
            try:
                skill_md = zf.read(member).decode("utf-8", errors="replace")
            except KeyError:
                continue
            records.append(_normalize_case(case, skill_md))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(records))
    return records


def load_skilltrust(limit: int | None = None) -> list[dict]:
    """Load SkillTrustBench cases: cache -> network -> committed fixture."""
    if CACHE_FILE.exists():
        records = json.loads(CACHE_FILE.read_text())
    else:
        try:
            records = _fetch_remote_records(limit)
        except (OSError, ValueError, KeyError):
            records = load_skilltrust_fixture()
            if limit is not None:
                records = records[:limit]
    if limit is not None:
        records = records[:limit]
    return records


def predict_skill(skill_record: dict) -> tuple[bool, list[Finding]]:
    """Authoring-stage prediction: malicious iff any scan rule fires."""
    findings = scan_skill(SkillDefinition(
        name=skill_record.get("skill_name", ""),
        body=synthesize_skill_body(skill_record),
    ))
    return bool(findings), findings


def _binary_metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4)}


def _per_category(predictions: list[dict]) -> dict[str, dict]:
    breakdown: dict[str, dict] = {}
    for pred in predictions:
        entry = breakdown.setdefault(pred["label"], {"cases": 0, "detected": 0})
        entry["cases"] += 1
        if pred["label"] != "benign" and pred["predicted_malicious"]:
            entry["detected"] += 1
    for label, entry in sorted(breakdown.items()):
        if label == "benign":
            flagged = sum(
                1 for p in predictions
                if p["label"] == "benign" and p["predicted_malicious"]
            )
            entry["false_positives"] = flagged
            entry["false_positive_rate"] = round(
                flagged / entry["cases"], 4) if entry["cases"] else 0.0
        else:
            entry["detection_rate"] = round(
                entry["detected"] / entry["cases"], 4) if entry["cases"] else 0.0
    return breakdown


def run_skilltrust_benchmark(records: list[dict] | None = None) -> dict:
    """Grade skill_scan predictions against SkillTrustBench labels.

    Deterministic tier only. Pass ``records=load_skilltrust_fixture()`` for
    the fast offline run; default loads cache/network/fixture corpus.
    """
    if records is None:
        records = load_skilltrust()

    predictions: list[dict] = []
    for record in records:
        malicious, findings = predict_skill(record)
        predictions.append({
            "skill_name": record.get("skill_name", ""),
            "label": record.get("label", "benign"),
            "predicted_malicious": malicious,
            "finding_codes": sorted({f.code for f in findings}),
        })

    cm = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for pred in predictions:
        is_threat = pred["label"] != "benign"
        if is_threat and pred["predicted_malicious"]:
            cm["tp"] += 1
        elif not is_threat and pred["predicted_malicious"]:
            cm["fp"] += 1
        elif not is_threat:
            cm["tn"] += 1
        else:
            cm["fn"] += 1

    metrics = _binary_metrics(cm["tp"], cm["fp"], cm["fn"])
    total = len(predictions)
    accuracy = (cm["tp"] + cm["tn"]) / total if total else 0.0

    sybil_findings = cluster_similarity([
        {"name": r.get("skill_name", ""), "description": r.get("description", "")}
        for r in records
    ])

    return {
        "benchmark": "skilltrust",
        "total_cases": total,
        "accuracy": round(accuracy, 4),
        **metrics,
        "confusion": cm,
        "per_category": _per_category(predictions),
        "predictions": predictions,
        "sybil_clusters_detected": len(sybil_findings),
        "measurement": {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "deterministic-rules",
            "upstream_model": None,
        },
    }


def render_skilltrust_md(report: dict, path: Path) -> None:
    lines = [
        "# Benchmark Results: SkillTrustBench (skill_scan validation)",
        "",
        f"Corpus: **{report['total_cases']} cases** distilled from 62,652 "
        "marketplace skills across 9 threat categories "
        "(HuggingFace cuhk-zhuque/SkillTrustBench). Each case is synthesized "
        "into SKILL.md text and graded by archon_core.security.skill_scan.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Accuracy | **{report['accuracy']:.1%}** |",
        f"| Precision | **{report['precision']:.1%}** |",
        f"| Recall | **{report['recall']:.1%}** |",
        f"| F1 | **{report['f1']:.1%}** |",
        "",
        "| Category | Cases | Detected | Rate |",
        "|---|---|---|---|",
    ]
    for label, s in report["per_category"].items():
        if label == "benign":
            lines.append(
                f"| {label} | {s['cases']} | {s['false_positives']} FP "
                f"| {s['false_positive_rate']:.1%} |"
            )
        else:
            lines.append(
                f"| {label} | {s['cases']} | {s['detected']} "
                f"| {s['detection_rate']:.1%} |"
            )
    m = report["measurement"]
    lines += [
        "",
        "## Methodology",
        "",
        f"- Attempt budget: {m['attempt_budget']} (single static attempt per case)",
        f"- Adaptivity: {m['adaptivity']}",
        f"- Judge: {m['judge']} (fully offline, reproducible)",
        f"- Upstream model: {m['upstream_model']} (deterministic scanner only)",
        f"- Sybil/stuffing clusters found by retrieval stage: "
        f"{report['sybil_clusters_detected']}",
        "",
        "## Context",
        "",
        "Prediction is malicious iff any authoring-stage rule fires on the "
        "synthesized SKILL.md body. Lifecycle stages beyond authoring "
        "(retrieval clustering, evolution diffing) require corpus context "
        "and are reported as counts, not per-case verdicts. Reproduce with "
        "`uv run python -m archon_benchmarks.skilltrust`.",
        "",
    ]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    import sys

    report = run_skilltrust_benchmark()
    print(json.dumps(report, indent=2))
    if len(sys.argv) > 1:
        render_skilltrust_md(report, Path(sys.argv[1]))
