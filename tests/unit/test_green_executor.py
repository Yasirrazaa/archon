"""Unit tests for archon.green_executor."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from a2a.server.agent_execution import RequestContext
from a2a.server.events import EventQueue
from a2a.types import Task
from a2a.utils.errors import ServerError

from archon.green_executor import GreenAgent, GreenExecutor
from archon.models import EvalRequest


class MockGreenAgent(GreenAgent):
    """Mock green agent for testing."""

    def __init__(self, should_succeed: bool = True):
        self.should_succeed = should_succeed
        self.validate_called = False
        self.run_eval_called = False

    async def run_eval(self, request: EvalRequest, updater) -> None:
        self.run_eval_called = True
        if not self.should_succeed:
            raise RuntimeError("Agent error")

    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        self.validate_called = True
        return True, "ok"


class TestGreenAgent:
    """Tests for GreenAgent abstract base class."""

    def test_abstract_methods(self):
        """Test that GreenAgent has required abstract methods."""
        assert hasattr(GreenAgent, "run_eval")
        assert hasattr(GreenAgent, "validate_request")


class TestGreenExecutor:
    """Tests for GreenExecutor."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock RequestContext."""
        context = MagicMock(spec=RequestContext)
        context.get_user_input.return_value = '{"participants": {"attacker": "http://attacker:9021", "defender": "http://defender:9020"}, "config": {"scenario_type": "test"}}'
        msg = MagicMock()
        msg.context_id = "test-context-id"
        context.message = msg
        context.context_id = "test-context-id"
        return context

    @pytest.fixture
    def mock_context_no_message(self):
        """Create a mock RequestContext without message."""
        context = MagicMock(spec=RequestContext)
        context.get_user_input.return_value = '{"participants": {"attacker": "http://attacker:9021", "defender": "http://defender:9020"}, "config": {"scenario_type": "test"}}'
        context.message = None
        context.context_id = "test-context-id"
        return context

    @pytest.fixture
    def mock_event_queue(self):
        """Create a mock EventQueue."""
        return MagicMock(spec=EventQueue)

    @pytest.fixture
    def mock_updater(self):
        """Create a mock TaskUpdater."""
        updater = AsyncMock()
        updater.update_status = AsyncMock()
        updater.complete = AsyncMock()
        updater.failed = AsyncMock()
        return updater

    @pytest.mark.asyncio
    async def test_execute_valid_request(self, mock_context, mock_event_queue, mock_updater):
        """Test executing a valid request."""
        with patch("archon.green_executor.new_task") as mock_new_task, \
             patch("archon.green_executor.TaskUpdater", return_value=mock_updater):

            mock_task = MagicMock(spec=Task)
            mock_task.id = "test-task-id"
            mock_task.context_id = "test-context-id"
            mock_new_task.return_value = mock_task

            agent = MockGreenAgent(should_succeed=True)
            executor = GreenExecutor(agent)

            await executor.execute(mock_context, mock_event_queue)

            # Verify agent methods were called
            assert agent.validate_called
            assert agent.run_eval_called

            # Verify task was created and enqueued
            mock_new_task.assert_called_once()
            mock_event_queue.enqueue_event.assert_called_once()

            # Verify status updates
            mock_updater.update_status.assert_called()
            mock_updater.complete.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_invalid_request(self, mock_context, mock_event_queue, mock_updater):
        """Test executing with invalid request."""
        with patch("archon.green_executor.new_task") as mock_new_task, \
             patch("archon.green_executor.TaskUpdater", return_value=mock_updater):

            mock_task = MagicMock(spec=Task)
            mock_task.id = "test-task-id"
            mock_task.context_id = "test-context-id"
            mock_new_task.return_value = mock_task

            agent = MockGreenAgent(should_succeed=True)
            # Make validation fail
            agent.validate_request = MagicMock(return_value=(False, "Invalid request"))
            executor = GreenExecutor(agent)

            with pytest.raises(ServerError) as exc_info:
                await executor.execute(mock_context, mock_event_queue)

            # Verify failure - ServerError with InvalidParamsError
            assert exc_info.value.error.message == "Invalid request"

    @pytest.mark.asyncio
    async def test_execute_missing_message(self, mock_context_no_message, mock_event_queue):
        """Test executing with missing message."""
        agent = MockGreenAgent(should_succeed=True)
        executor = GreenExecutor(agent)

        with pytest.raises(ServerError) as exc_info:
            await executor.execute(mock_context_no_message, mock_event_queue)

        assert "Missing message" in exc_info.value.error.message

    @pytest.mark.asyncio
    async def test_execute_agent_error(self, mock_context, mock_event_queue, mock_updater):
        """Test handling of agent runtime error."""
        with patch("archon.green_executor.new_task") as mock_new_task, \
             patch("archon.green_executor.TaskUpdater", return_value=mock_updater):

            mock_task = MagicMock(spec=Task)
            mock_task.id = "test-task-id"
            mock_task.context_id = "test-context-id"
            mock_new_task.return_value = mock_task

            agent = MockGreenAgent(should_succeed=False)
            executor = GreenExecutor(agent)

            with pytest.raises(ServerError) as exc_info:
                await executor.execute(mock_context, mock_event_queue)

            # Verify failed status was sent
            mock_updater.failed.assert_called_once()
            assert exc_info.value.error.message == "Agent error"

    @pytest.mark.asyncio
    async def test_cancel_raises_error(self, mock_context, mock_event_queue):
        """Test that cancel raises UnsupportedOperationError."""
        agent = MockGreenAgent()
        executor = GreenExecutor(agent)

        with pytest.raises(ServerError) as exc_info:
            await executor.cancel(mock_context, mock_event_queue)

        assert exc_info.value.error.code == -32004  # UnsupportedOperationError code
        assert "supported" in exc_info.value.error.message.lower()


class TestGreenExecutorIntegration:
    """Integration tests for GreenExecutor with real components."""

    @pytest.mark.asyncio
    async def test_full_flow_with_mock_agent(self):
        """Test full execution flow with a mock agent."""
        # This test uses more realistic mocking
        context = MagicMock(spec=RequestContext)
        context.get_user_input.return_value = '{"participants": {"attacker": "http://attacker:9021", "defender": "http://defender:9020"}, "config": {"scenario_type": "portfolioiq", "num_rounds": 7}}'
        msg = MagicMock()
        msg.context_id = "test-context-id"
        context.message = msg
        context.context_id = "test-context-id"

        event_queue = MagicMock(spec=EventQueue)

        agent = MockGreenAgent()
        executor = GreenExecutor(agent)

        with patch("archon.green_executor.new_task") as mock_new_task, \
             patch("archon.green_executor.TaskUpdater") as mock_updater_class:

            mock_task = MagicMock(spec=Task)
            mock_task.id = "test-task"
            mock_task.context_id = "test-context-id"
            mock_new_task.return_value = mock_task

            mock_updater = AsyncMock()
            mock_updater.update_status = AsyncMock()
            mock_updater.complete = AsyncMock()
            mock_updater_class.return_value = mock_updater

            await executor.execute(context, event_queue)

            assert agent.run_eval_called
            mock_new_task.assert_called_once()
            mock_updater.update_status.assert_called()
            mock_updater.complete.assert_called_once()
