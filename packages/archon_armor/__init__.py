"""archon-armor: the deployable defense proxy.

Exposes an OpenAI-compatible ``/v1/chat/completions`` endpoint protected by
the Archon defense pipeline. Any agent can adopt it by pointing its
``OPENAI_BASE_URL`` at this service and sending its registered identity via
the ``X-Agent-ID`` header.
"""

from .app import create_app
from .upstream import HTTPOpenAIUpstream, LLMUpstream, UpstreamError

__all__ = ["create_app", "HTTPOpenAIUpstream", "LLMUpstream", "UpstreamError"]

