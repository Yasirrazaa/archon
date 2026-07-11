"""Test configuration and fixtures for Archon tests."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from archon.models import EvalRequest, EvalResult


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_eval_request() -> EvalRequest:
    """Create a sample EvalRequest for testing."""
    return EvalRequest(
        participants={
            "attacker": "http://attacker:9021",
            "defender": "http://defender:9020",
        },
        config={
            "scenario_type": "portfolioiq",
            "num_rounds": 7,
        }
    )


@pytest.fixture
def sample_eval_result() -> EvalResult:
    """Create a sample EvalResult for testing."""
    return EvalResult(
        winner="defender",
        detail={
            "team_name": "test-team",
            "scenario_type": "portfolioiq",
            "winner": "defender",
            "manipulation_round": None,
            "rounds_defended": 7,
            "total_rounds": 7,
            "battle_log": [],
        }
    )


@pytest.fixture
def mock_httpx_client() -> AsyncMock:
    """Create a mock httpx client."""
    client = AsyncMock()
    return client


@pytest.fixture
def mock_a2a_card_resolver() -> AsyncMock:
    """Create a mock A2A card resolver."""
    resolver = AsyncMock()
    return resolver
