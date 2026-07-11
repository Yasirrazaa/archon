"""Unit tests for archon.client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from a2a.types import (
    AgentCard,
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatusUpdateEvent,
    TaskArtifactUpdateEvent,
    TextPart,
    DataPart,
)

from archon.client import create_message, merge_parts, send_message


class TestCreateMessage:
    """Tests for create_message function."""

    def test_create_user_message(self):
        """Test creating a user message."""
        msg = create_message(role=Role.user, text="Hello", context_id="ctx-123")
        assert msg.role == Role.user
        assert len(msg.parts) == 1
        assert isinstance(msg.parts[0].root, TextPart)
        assert msg.parts[0].root.text == "Hello"
        assert msg.context_id == "ctx-123"

    def test_create_assistant_message(self):
        """Test creating an assistant message."""
        msg = create_message(role=Role.agent, text="Hi there")
        assert msg.role == Role.agent
        assert msg.parts[0].root.text == "Hi there"

    def test_create_message_without_context_id(self):
        """Test creating message without context ID."""
        msg = create_message(text="Test")
        assert msg.context_id is None

    def test_message_has_unique_id(self):
        """Test that each message gets a unique ID."""
        msg1 = create_message(text="Test 1")
        msg2 = create_message(text="Test 2")
        assert msg1.message_id != msg2.message_id


class TestMergeParts:
    """Tests for merge_parts function."""

    def test_merge_text_parts(self):
        """Test merging text parts."""
        parts = [
            Part(TextPart(kind="text", text="Hello")),
            Part(TextPart(kind="text", text="World")),
        ]
        result = merge_parts(parts)
        assert result == "Hello\nWorld"

    def test_merge_data_parts(self):
        """Test merging data parts."""
        parts = [
            Part(DataPart(kind="data", data={"key": "value"})),
            Part(DataPart(kind="data", data={"foo": "bar"})),
        ]
        result = merge_parts(parts)
        # DataPart nests data under 'data' key
        assert "key" in result
        assert "foo" in result

    def test_merge_mixed_parts(self):
        """Test merging mixed text and data parts."""
        parts = [
            Part(TextPart(kind="text", text="Text part")),
            Part(DataPart(kind="data", data={"key": "value"})),
        ]
        result = merge_parts(parts)
        assert "Text part" in result
        assert "key" in result

    def test_merge_empty_parts(self):
        """Test merging empty parts list."""
        result = merge_parts([])
        assert result == ""


class TestSendMessage:
    """Tests for send_message function."""

    def test_send_message_importable(self):
        """Test that send_message function can be imported."""
        from archon.client import send_message
        assert callable(send_message)

    def test_create_message_importable(self):
        """Test that create_message function can be imported."""
        from archon.client import create_message
        assert callable(create_message)

    def test_merge_parts_importable(self):
        """Test that merge_parts function can be imported."""
        from archon.client import merge_parts
        assert callable(merge_parts)