"""Archon CLI client for running scenarios."""
import asyncio
import json
import sys
import tomllib
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from a2a.types import (
    AgentCard,
    DataPart,
    Message,
    Part,
    TaskArtifactUpdateEvent,
    TaskStatusUpdateEvent,
    TextPart,
)

from archon.client import send_message
from archon.models import EvalRequest

ConsumerCallback = Callable[[Any, AgentCard], Awaitable[None]]


def parse_toml(d: dict[str, Any]) -> tuple[EvalRequest, str]:
    green = d.get("green_agent")
    if not isinstance(green, dict) or "endpoint" not in green:
        raise ValueError("green.endpoint is required in TOML")

    green_endpoint: str = green["endpoint"]

    # collect participants
    from pydantic import HttpUrl
    parts: dict[str, HttpUrl] = {}
    for p in d.get("participants", []):
        if isinstance(p, dict):
            role = p.get("role")
            endpoint = p.get("endpoint")
            if role and endpoint:
                parts[role] = HttpUrl(endpoint)

    eval_req = EvalRequest(
        participants=parts,
        config=d.get("config", {}) or {}
    )
    return eval_req, green_endpoint


def print_parts(parts: list[Part], task_state: str | None = None) -> None:
    text_parts: list[str] = []
    data_parts: list[Any] = []

    for part in parts:
        if isinstance(part.root, TextPart):
            try:
                data_item = json.loads(part.root.text)
                data_parts.append(data_item)
            except Exception:
                text_parts.append(part.root.text.strip())
        elif isinstance(part.root, DataPart):
            data_parts.append(part.root.data)

    output: list[str] = []
    if task_state:
        output.append(f"[Status: {task_state}]")
    if text_parts:
        output.append("\n".join(text_parts))
    if data_parts:
        output.extend(json.dumps(item, indent=2) for item in data_parts)



async def event_consumer(event: tuple[Any, Any] | Message, card: AgentCard) -> None:
    match event:
        case Message() as msg:
            print_parts(msg.parts)

        case (task, TaskStatusUpdateEvent() as status_event):
            status = status_event.status
            parts = status.message.parts if status.message else []
            print_parts(parts, status.state.value)
            if status.state.value == "completed":
                pass

        case (task, TaskArtifactUpdateEvent() as artifact_event):
            print_parts(artifact_event.artifact.parts, "Artifact update")

        case task, None:
            status = task.status
            parts = status.message.parts if status.message else []
            print_parts(parts, task.status.state.value)

        case _:
            pass


async def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run scenario client")
    parser.add_argument("scenario", help="Path to scenario TOML file")
    parser.add_argument("--normal-user", action="store_true",
                        help="Run normal user helpfulness test instead of adversarial battle")
    args = parser.parse_args()

    path = Path(args.scenario)
    if not path.exists():
        sys.exit(1)

    toml_data = path.read_text()
    data = tomllib.loads(toml_data)

    req, green_url = parse_toml(data)

    # Set normal_user mode in config if flag provided
    # Copy topics from root level normal_user.topics to config.normal_user.topics
    if args.normal_user:
        nu_data = data.get("normal_user", {})
        topics = nu_data.get("topics", [])
        req.config["normal_user"] = {
            "enabled": True,
            "topics": topics
        }

    msg = req.model_dump_json()
    await send_message(msg, green_url, streaming=True, consumer=event_consumer)


if __name__ == "__main__":
    asyncio.run(main())
