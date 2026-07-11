"""Unit tests for archon.models."""

import pytest
from pydantic import ValidationError

from archon.models import EvalRequest, EvalResult


class TestEvalRequest:
    """Tests for EvalRequest model."""

    def test_valid_request(self):
        """Test creating a valid EvalRequest."""
        request = EvalRequest(
            participants={
                "attacker": "http://attacker:9021",
                "defender": "http://defender:9020",
            },
            config={"scenario_type": "portfolioiq", "num_rounds": 7},
        )
        assert str(request.participants["attacker"]) == "http://attacker:9021/"
        assert str(request.participants["defender"]) == "http://defender:9020/"
        assert request.config["scenario_type"] == "portfolioiq"

    def test_valid_request_with_normal_user(self):
        """Test creating EvalRequest with normal_user config."""
        request = EvalRequest(
            participants={
                "defender": "http://defender:9020",
                "normal_user": "http://normal_user:9022",
            },
            config={
                "scenario_type": "portfolioiq",
                "num_rounds": 7,
                "normal_user": {
                    "enabled": True,
                    "topics": [{"topic": "test", "expected_concepts": ["test"]}],
                },
            },
        )
        assert request.config["normal_user"]["enabled"] is True

    def test_invalid_participants_missing_attacker(self):
        """Test that missing attacker is accepted (no validation in model)."""
        # The model doesn't require attacker field - it's just a dict
        request = EvalRequest(
            participants={"defender": "http://defender:9020"},
            config={"scenario_type": "portfolioiq"},
        )
        assert "defender" in request.participants
        assert "attacker" not in request.participants

    def test_invalid_url(self):
        """Test that invalid URL raises validation error."""
        with pytest.raises(ValidationError):
            EvalRequest(
                participants={
                    "attacker": "not-a-url",
                    "defender": "http://defender:9020",
                },
                config={"scenario_type": "portfolioiq"},
            )

    def test_empty_config(self):
        """Test that empty config is allowed."""
        request = EvalRequest(
            participants={
                "attacker": "http://attacker:9021",
                "defender": "http://defender:9020",
            },
            config={},
        )
        assert request.config == {}


class TestEvalResult:
    """Tests for EvalResult model."""

    def test_valid_result(self):
        """Test creating a valid EvalResult."""
        result = EvalResult(
            winner="defender",
            detail={
                "team_name": "test-team",
                "scenario_type": "portfolioiq",
                "winner": "defender",
                "rounds_defended": 7,
            },
        )
        assert result.winner == "defender"
        assert result.detail["team_name"] == "test-team"

    def test_attacker_winner(self):
        """Test result with attacker as winner."""
        result = EvalResult(
            winner="attacker",
            detail={
                "manipulation_round": 3,
                "extracted_value": "Low",
            },
        )
        assert result.winner == "attacker"
        assert result.detail["manipulation_round"] == 3

    def test_invalid_winner(self):
        """Test that invalid winner is accepted (no validation in model)."""
        # The model doesn't validate winner values - it's just a string
        result = EvalResult(
            winner="invalid",
            detail={},
        )
        assert result.winner == "invalid"
