"""TDD Phase 7: archon CLI — register / scan / serve with CI exit codes."""

import json

import pytest
from archon_cli.main import main


@pytest.fixture
def registry_path(tmp_path):
    return str(tmp_path / "registry.db")


def test_register_prints_secret_once_and_registers_agent(registry_path, capsys):
    rc = main(["register", "--registry", registry_path, "--agent-id", "a1", "--name", "Agent One"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["agent_id"] == "a1"
    assert len(payload["api_secret"]) >= 32

    # Registering again fails cleanly with exit code 1
    rc = main(["register", "--registry", registry_path, "--agent-id", "a1", "--name", "dup"])
    assert rc == 1


def test_scan_outputs_json_report_and_exit_zero_when_threshold_met(registry_path, capsys):
    main(["register", "--registry", registry_path, "--agent-id", "a1", "--name", "A"])
    capsys.readouterr()  # discard register output
    rc = main(
        [
            "scan", "--registry", registry_path, "--agent-id", "a1",
            "--min-block-rate", "0.1", "--json",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "completed"
    assert report["summary"]["total_probes"] > 0
    assert "block_rate" in report["summary"]
    assert report["summary"]["control_passed"] is True


def test_scan_ci_mode_fails_when_block_rate_below_threshold(registry_path):
    main(["register", "--registry", registry_path, "--agent-id", "a1", "--name", "A"])
    rc = main(
        [
            "scan", "--registry", registry_path, "--agent-id", "a1",
            "--min-block-rate", "0.999", "--ci",
        ]
    )
    assert rc == 1


def test_scan_fails_with_error_code_for_unknown_agent(registry_path):
    rc = main(["scan", "--registry", registry_path, "--agent-id", "ghost", "--ci"])
    assert rc == 2


def test_scan_human_output_when_not_json(registry_path, capsys):
    main(["register", "--registry", registry_path, "--agent-id", "a1", "--name", "A"])
    capsys.readouterr()
    rc = main(["scan", "--registry", registry_path, "--agent-id", "a1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "block_rate" in out or "Block rate" in out.lower() or "%" in out


def test_serve_invokes_uvicorn_with_wired_app(registry_path, monkeypatch):
    captured = {}

    def fake_run(app, host="0.0.0.0", port=8080, **kwargs):
        captured["app"] = app
        captured["port"] = port

    monkeypatch.setattr("archon_cli.main._run_uvicorn", fake_run)
    rc = main(
        ["serve", "--registry", registry_path, "--port", "9099",
         "--upstream-base-url", "https://api.upstream.test/v1"]
    )
    assert rc == 0
    assert captured["port"] == 9099
    assert callable(captured["app"]) or captured["app"] is not None


def test_no_args_shows_help_and_returns_nonzero():
    rc = main([])
    assert rc != 0
