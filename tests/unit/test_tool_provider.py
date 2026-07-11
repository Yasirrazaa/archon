"""Unit tests for archon.tool_provider."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from archon.tool_provider import ToolProvider


class TestToolProvider:
    """Tests for ToolProvider class."""

    @pytest.fixture
    def tool_provider(self):
        """Create a ToolProvider instance."""
        return ToolProvider()

    @pytest.fixture
    def mock_send_message(self):
        """Mock the send_message function."""
        with patch("archon.tool_provider.send_message") as mock:
            yield mock

    @pytest.mark.asyncio
    async def test_talk_to_agent_new_conversation(self, tool_provider, mock_send_message):
        """Test talking to agent with new conversation."""
        mock_send_message.return_value = {
            "response": "Hello from agent",
            "context_id": "ctx-123",
            "status": "completed",
        }

        response = await tool_provider.talk_to_agent(
            message="Hello",
            url="http://agent:9020",
            new_conversation=True,
        )

        assert response == "Hello from agent"
        mock_send_message.assert_called_once_with(
            message="Hello",
            base_url="http://agent:9020",
            context_id=None,
        )
        # Context ID should be stored
        assert tool_provider._context_ids["http://agent:9020"] == "ctx-123"

    @pytest.mark.asyncio
    async def test_talk_to_agent_continue_conversation(self, tool_provider, mock_send_message):
        """Test talking to agent continuing existing conversation."""
        # Pre-populate context ID
        tool_provider._context_ids["http://agent:9020"] = "existing-ctx-456"

        mock_send_message.return_value = {
            "response": "Continued response",
            "context_id": "existing-ctx-456",
            "status": "completed",
        }

        response = await tool_provider.talk_to_agent(
            message="Continue",
            url="http://agent:9020",
            new_conversation=False,
        )

        assert response == "Continued response"
        mock_send_message.assert_called_once_with(
            message="Continue",
            base_url="http://agent:9020",
            context_id="existing-ctx-456",
        )

    @pytest.mark.asyncio
    async def test_talk_to_agent_error_status(self, tool_provider, mock_send_message):
        """Test handling of error status from agent."""
        mock_send_message.return_value = {
            "response": "Error occurred",
            "context_id": "ctx-123",
            "status": "failed",
        }

        with pytest.raises(RuntimeError) as exc_info:
            await tool_provider.talk_to_agent(
                message="Hello",
                url="http://agent:9020",
            )

        assert "http://agent:9020 responded with:" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_talk_to_agent_missing_response(self, tool_provider, mock_send_message):
        """Test handling of missing response."""
        mock_send_message.return_value = {
            "context_id": "ctx-123",
            "status": "completed",
        }

        response = await tool_provider.talk_to_agent(
            message="Hello",
            url="http://agent:9020",
        )

        # Should return empty string if response missing
        assert response == ""

    def test_reset(self, tool_provider):
        """Test resetting context IDs."""
        tool_provider._context_ids = {"http://agent:9020": "ctx-123"}
        tool_provider.reset()
        assert tool_provider._context_ids == {}

    @pytest.mark.asyncio
    async def test_multiple_agents_separate_contexts(self, tool_provider, mock_send_message):
        """Test that multiple agents maintain separate contexts."""
        mock_send_message.side_effect = [
            {"response": "Agent 1 response", "context_id": "ctx-1", "status": "completed"},
            {"response": "Agent 2 response", "context_id": "ctx-2", "status": "completed"},
        ]

        resp1 = await tool_provider.talk_to_agent("Msg 1", "http://agent1:9020", new_conversation=True)
        resp2 = await tool_provider.talk_to_agent("Msg 2", "http://agent2:9020", new_conversation=True)

        assert resp1 == "Agent 1 response"
        assert resp2 == "Agent 2 response"
        assert tool_provider._context_ids["http://agent1:9020"] == "ctx-1"
        assert tool_provider._context_ids["http://agent2:9020"] == "ctx-2"
        assert mock_send_message.call_count == 2