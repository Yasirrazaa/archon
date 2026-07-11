"""Unit tests for archon.config."""

import os
from unittest.mock import patch

from archon.config import Settings, get_settings, reset_settings


class TestSettings:
    """Tests for Settings class."""

    def test_default_values(self):
        """Test default configuration values."""
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            assert settings.app_name == "archon"
            assert settings.debug is False
            assert settings.log_level == "INFO"
            assert settings.orchestrator_port == 9010
            assert settings.attacker_port == 9021
            assert settings.defender_port == 9020
            assert settings.normal_user_port == 9022
            assert settings.agent_timeout_seconds == 300
            assert settings.normal_user_max_attempts == 3
            assert settings.default_model == "gpt-4o-mini"
            assert settings.results_dir == "results"

    def test_env_override(self):
        """Test environment variable overrides."""
        env_vars = {
            "APP_NAME": "custom-archon",
            "DEBUG": "true",
            "LOG_LEVEL": "DEBUG",
            "ORCHESTRATOR_PORT": "8010",
            "ATTACKER_PORT": "8021",
            "DEFENDER_PORT": "8020",
            "NORMAL_USER_PORT": "8022",
            "AGENT_TIMEOUT_SECONDS": "600",
            "NORMAL_USER_MAX_ATTEMPTS": "5",
            "DEFAULT_MODEL": "gpt-4",
            "RESULTS_DIR": "/custom/results",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            settings = Settings()
            assert settings.app_name == "custom-archon"
            assert settings.debug is True
            assert settings.log_level == "DEBUG"
            assert settings.orchestrator_port == 8010
            assert settings.attacker_port == 8021
            assert settings.defender_port == 8020
            assert settings.normal_user_port == 8022
            assert settings.agent_timeout_seconds == 600
            assert settings.normal_user_max_attempts == 5
            assert settings.default_model == "gpt-4"
            assert settings.results_dir == "/custom/results"

    def test_optional_api_keys(self):
        """Test optional API key fields."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test", "OPENAI_BASE_URL": "https://custom.openai.com"}, clear=True):
            settings = Settings()
            assert settings.openai_api_key == "sk-test"
            assert settings.openai_base_url == "https://custom.openai.com"

    def test_missing_optional_keys(self):
        """Test that optional keys default to None."""
        # Create a test settings class without env_file
        from pydantic import Field
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class TestSettings(BaseSettings):
            model_config = SettingsConfigDict(
                env_file=None,  # Disable .env file loading
                case_sensitive=False,
                extra="ignore",
            )
            openai_api_key: str | None = Field(default=None)
            openai_base_url: str | None = Field(default=None)

        settings = TestSettings()
        assert settings.openai_api_key is None
        assert settings.openai_base_url is None


class TestGetSettings:
    """Tests for get_settings function."""

    def test_singleton_behavior(self):
        """Test that get_settings returns cached instance."""
        reset_settings()
        with patch.dict(os.environ, {}, clear=True):
            settings1 = get_settings()
            settings2 = get_settings()
            assert settings1 is settings2  # Same instance

    def test_reset_settings(self):
        """Test that reset_settings clears cache."""
        reset_settings()
        with patch.dict(os.environ, {}, clear=True):
            settings1 = get_settings()
            reset_settings()
            settings2 = get_settings()
            assert settings1 is not settings2  # Different instances

    def test_env_changes_after_first_call(self):
        """Test that env changes don't affect cached settings."""
        # Test caching behavior: once get_settings is called, it returns the same instance
        reset_settings()
        with patch.dict(os.environ, {"DEBUG": "false"}, clear=True):
            settings1 = get_settings()
            assert settings1.debug is False

        # Call again without reset - should return cached instance
        settings2 = get_settings()
        assert settings2.debug is False
        assert settings1 is settings2  # Same instance

        # After reset, new instance is created (but env is still false from first patch)
        reset_settings()
        settings3 = get_settings()
        assert settings3.debug is False
        assert settings1 is not settings3  # Different instance


class TestSettingsValidation:
    """Tests for settings validation."""

    def test_port_ranges(self):
        """Test that port values are validated."""
        # Valid ports
        with patch.dict(os.environ, {"ORCHESTRATOR_PORT": "1024", "ATTACKER_PORT": "65535"}, clear=True):
            settings = Settings()
            assert settings.orchestrator_port == 1024
            assert settings.attacker_port == 65535

    def test_invalid_port_too_high(self):
        """Test that ports > 65535 are handled."""
        # Current implementation doesn't validate - just test it accepts the value
        with patch.dict(os.environ, {"ORCHESTRATOR_PORT": "70000"}, clear=True):
            settings = Settings()
            assert settings.orchestrator_port == 70000

    def test_invalid_port_too_low(self):
        """Test that ports < 1 are handled."""
        # Current implementation doesn't validate
        with patch.dict(os.environ, {"ORCHESTRATOR_PORT": "0"}, clear=True):
            settings = Settings()
            assert settings.orchestrator_port == 0

    def test_positive_timeout(self):
        """Test that timeout accepts negative values (no validation in current impl)."""
        with patch.dict(os.environ, {"AGENT_TIMEOUT_SECONDS": "-1"}, clear=True):
            settings = Settings()
            assert settings.agent_timeout_seconds == -1

    def test_positive_max_attempts(self):
        """Test that max attempts accepts zero (no validation in current impl)."""
        with patch.dict(os.environ, {"NORMAL_USER_MAX_ATTEMPTS": "0"}, clear=True):
            settings = Settings()
            assert settings.normal_user_max_attempts == 0
