"""Tests for execution mode scaling module.

Based on NeuralShield's architecture: maps suspicion score to 4 execution modes
with varying trust levels and feature availability.
"""
import pytest

from scenarios.security_arena.agents.defender.execution_modes import (
    ExecutionMode,
    ExecutionModeSelector,
    ModeConfig,
)


class TestExecutionMode:
    def test_all_modes_defined(self):
        modes = [
            ExecutionMode.STANDARD,
            ExecutionMode.CAUTIOUS,
            ExecutionMode.CONSERVATIVE,
            ExecutionMode.MINIMAL,
        ]
        assert len(modes) == 4

    def test_mode_values(self):
        assert ExecutionMode.STANDARD.value == "standard"
        assert ExecutionMode.CAUTIOUS.value == "cautious"
        assert ExecutionMode.CONSERVATIVE.value == "conservative"
        assert ExecutionMode.MINIMAL.value == "minimal"


class TestModeConfig:
    def test_config_fields(self):
        config = ModeConfig(
            output_trust=0.8,
            allow_recommendations=True,
            allow_specific_claims=True,
            response_style="standard",
        )
        assert config.output_trust == 0.8
        assert config.allow_recommendations is True
        assert config.allow_specific_claims is True
        assert config.response_style == "standard"

    def test_standard_config(self):
        config = ModeConfig(
            output_trust=1.0,
            allow_recommendations=True,
            allow_specific_claims=True,
            response_style="standard",
        )
        assert config.output_trust == 1.0
        assert config.allow_recommendations is True
        assert config.allow_specific_claims is True

    def test_minimal_config(self):
        config = ModeConfig(
            output_trust=0.2,
            allow_recommendations=False,
            allow_specific_claims=False,
            response_style="minimal",
        )
        assert config.output_trust == 0.2
        assert config.allow_recommendations is False
        assert config.allow_specific_claims is False


class TestExecutionModeSelector:
    @pytest.fixture
    def selector(self):
        return ExecutionModeSelector()

    def test_low_suspicion_selects_standard(self, selector):
        assert selector.select(0.0) == ExecutionMode.STANDARD
        assert selector.select(0.1) == ExecutionMode.STANDARD
        assert selector.select(0.19) == ExecutionMode.STANDARD

    def test_medium_suspicion_selects_cautious(self, selector):
        assert selector.select(0.2) == ExecutionMode.CAUTIOUS
        assert selector.select(0.35) == ExecutionMode.CAUTIOUS
        assert selector.select(0.49) == ExecutionMode.CAUTIOUS

    def test_high_suspicion_selects_conservative(self, selector):
        assert selector.select(0.5) == ExecutionMode.CONSERVATIVE
        assert selector.select(0.65) == ExecutionMode.CONSERVATIVE
        assert selector.select(0.79) == ExecutionMode.CONSERVATIVE

    def test_very_high_suspicion_selects_minimal(self, selector):
        assert selector.select(0.8) == ExecutionMode.MINIMAL
        assert selector.select(0.9) == ExecutionMode.MINIMAL
        assert selector.select(1.0) == ExecutionMode.MINIMAL

    def test_boundary_standard_to_cautious(self, selector):
        assert selector.select(0.199) == ExecutionMode.STANDARD
        assert selector.select(0.2) == ExecutionMode.CAUTIOUS

    def test_boundary_cautious_to_conservative(self, selector):
        assert selector.select(0.499) == ExecutionMode.CAUTIOUS
        assert selector.select(0.5) == ExecutionMode.CONSERVATIVE

    def test_boundary_conservative_to_minimal(self, selector):
        assert selector.select(0.799) == ExecutionMode.CONSERVATIVE
        assert selector.select(0.8) == ExecutionMode.MINIMAL

    def test_zero_suspicion(self, selector):
        assert selector.select(0.0) == ExecutionMode.STANDARD

    def test_one_suspicion(self, selector):
        assert selector.select(1.0) == ExecutionMode.MINIMAL


class TestGetConfig:
    @pytest.fixture
    def selector(self):
        return ExecutionModeSelector()

    def test_standard_config_trust(self, selector):
        config = selector.get_config(ExecutionMode.STANDARD)
        assert config.output_trust == 1.0

    def test_cautious_config_trust(self, selector):
        config = selector.get_config(ExecutionMode.CAUTIOUS)
        assert config.output_trust == 0.8

    def test_conservative_config_trust(self, selector):
        config = selector.get_config(ExecutionMode.CONSERVATIVE)
        assert config.output_trust == 0.5

    def test_minimal_config_trust(self, selector):
        config = selector.get_config(ExecutionMode.MINIMAL)
        assert config.output_trust == 0.2

    def test_standard_allows_recommendations(self, selector):
        config = selector.get_config(ExecutionMode.STANDARD)
        assert config.allow_recommendations is True
        assert config.allow_specific_claims is True

    def test_cautious_allows_recommendations(self, selector):
        config = selector.get_config(ExecutionMode.CAUTIOUS)
        assert config.allow_recommendations is True
        assert config.allow_specific_claims is True

    def test_conservative_no_recommendations(self, selector):
        config = selector.get_config(ExecutionMode.CONSERVATIVE)
        assert config.allow_recommendations is False
        assert config.allow_specific_claims is False

    def test_minimal_no_recommendations(self, selector):
        config = selector.get_config(ExecutionMode.MINIMAL)
        assert config.allow_recommendations is False
        assert config.allow_specific_claims is False

    def test_standard_response_style(self, selector):
        config = selector.get_config(ExecutionMode.STANDARD)
        assert config.response_style == "standard"

    def test_cautious_response_style(self, selector):
        config = selector.get_config(ExecutionMode.CAUTIOUS)
        assert config.response_style == "cautious"

    def test_conservative_response_style(self, selector):
        config = selector.get_config(ExecutionMode.CONSERVATIVE)
        assert config.response_style == "conservative"

    def test_minimal_response_style(self, selector):
        config = selector.get_config(ExecutionMode.MINIMAL)
        assert config.response_style == "minimal"

    def test_all_modes_have_configs(self, selector):
        for mode in ExecutionMode:
            config = selector.get_config(mode)
            assert isinstance(config, ModeConfig)
            assert 0.0 <= config.output_trust <= 1.0


class TestSelectAndGetConfigIntegration:
    def test_select_then_get_config(self):
        selector = ExecutionModeSelector()
        mode = selector.select(0.3)
        config = selector.get_config(mode)
        assert mode == ExecutionMode.CAUTIOUS
        assert config.output_trust == 0.8

    def test_full_range(self):
        selector = ExecutionModeSelector()
        test_cases = [
            (0.0, ExecutionMode.STANDARD, 1.0),
            (0.25, ExecutionMode.CAUTIOUS, 0.8),
            (0.6, ExecutionMode.CONSERVATIVE, 0.5),
            (0.95, ExecutionMode.MINIMAL, 0.2),
        ]
        for score, expected_mode, expected_trust in test_cases:
            mode = selector.select(score)
            config = selector.get_config(mode)
            assert mode == expected_mode
            assert config.output_trust == expected_trust
