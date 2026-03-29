#!/usr/bin/env python3
"""
Attacker Agent - Red team agent for security testing.

Receives scenario context as JSON, builds strategic prompts, and generates attacks.
Works across different scenarios by adapting to context dynamically.
"""

import argparse
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

from openai import AsyncOpenAI

# Load custom attacker modules
import sys
sys.path.append(str(Path(__file__).parent))
import pyrit_converters
import goat_loop

# Load templates
_template_dir = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_template_dir), trim_blocks=True, lstrip_blocks=True)
_system_template = _env.get_template("system.j2")
_user_template = _env.get_template("user.j2")
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard, AgentCapabilities, TaskState,
    InvalidParamsError, UnsupportedOperationError, Task
)
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attacker")


@dataclass
class ScenarioContext:
    """Scenario context from orchestrator for attack generation."""
    attack_type: str                        # INJECTION (embedded) or DIRECT (message)
    domain_description: str                 # Domain/system being attacked
    attack_goal: str                        # What attacker is trying to achieve
    attack_constraints: list[str]           # Rules attacker must follow
    max_number_of_rounds: int               # Maximum battle rounds
    defender_role: str                      # Defender's role description
    defender_task: str                      # What defender does
    output_format: str                      # Expected defender output format
    input_format_template: str              # Template with PLACE_ATTACK_HERE
    current_round: int = 0                  # Current round (0-indexed)
    battle_history: list[dict] = field(default_factory=list)  # Previous rounds

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioContext":
        return cls(
            attack_type=d.get("attack_type", "DIRECT"),
            domain_description=d.get("domain_description", ""),
            attack_goal=d.get("attack_goal", ""),
            attack_constraints=d.get("attack_constraints", []),
            max_number_of_rounds=d.get("max_number_of_rounds", 5),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            output_format=d.get("output_format", ""),
            input_format_template=d.get("input_format_template", ""),
            current_round=d.get("current_round", 0),
            battle_history=d.get("battle_history", []),
        )


class Attacker(AgentExecutor):
    """Red team attacker that generates strategic attacks based on scenario context."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL")
        )
        self.model = model

        # State management for the 7 rounds
        self.round_data: dict[int, dict] = {}

    def _render(self, template, ctx: ScenarioContext, **extra) -> str:
        """Render a Jinja2 template with the scenario context and extra data."""
        return template.render(**vars(ctx), **extra)

    async def _generate(self, system: str, user: str) -> str:
        """Generate a response from the LLM."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.8 # Slightly higher temp for creative attacks
        )
        content = response.choices[0].message.content
        return content if content is not None else ""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Generate an attack based on scenario context."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            # Parse JSON context
            message_text = context.get_user_input()
            ctx = ScenarioContext.from_dict(json.loads(message_text))
            
            # Reset state if it's round 0 (new battle)
            if ctx.current_round == 0:
                self.round_data = {}
                doc_type = goat_loop.guess_document_type(ctx.defender_role, ctx.defender_task)
                fragments = goat_loop.build_reconstruction_fragments(ctx.attack_goal)
                self.round_data[0] = {
                    "doc_type": doc_type,
                    "target_fragments": fragments,
                    "response_tone": "unknown",
                    "best_technique_for_next_turn": "T7" if ctx.attack_type == "DIRECT" else "T9"
                }

            logger.info("Round %d: Type=%s, History=%d",
                        ctx.current_round + 1, ctx.attack_type, len(ctx.battle_history))

            # Retrieve state
            stored_rounds = dict(self.round_data)

            # Generate attack via LLM
            raw_output = await self._generate(
                self._render(_system_template, ctx),
                self._render(_user_template, ctx, stored_rounds=stored_rounds)
            )

            # Parse the inline <score> block
            parsed_result = goat_loop.parse_inline_score(raw_output)
            cleaned_message = parsed_result["cleaned_text"]
            
            # Save state for the *next* round to use
            self.round_data[ctx.current_round] = {
                "score": parsed_result["score"],
                "partial_leak": parsed_result["partial_leak"],
                "response_tone": parsed_result["response_tone"],
                "best_technique_for_next_turn": parsed_result["best_technique_for_next_turn"]
            }
            
            # Apply PyRIT converters if it's an INJECTION scenario and we're struggling
            if ctx.attack_type == "INJECTION" and ctx.current_round > 2 and parsed_result.get("score", 0) < 2:
                # If we're failing injection, start applying heavy obfuscation to evade filters
                cleaned_message = pyrit_converters.apply_converter(cleaned_message, ctx.current_round)

            logger.info("Generated attack (Raw: %d chars, Cleaned: %d chars)", len(raw_output), len(cleaned_message))
            logger.info("Parsed score: %s, Next Tech: %s", parsed_result['score'], parsed_result['best_technique_for_next_turn'])
            
            await updater.update_status(TaskState.completed, new_agent_text_message(cleaned_message))
            
        except Exception as e:
            logger.error("Attacker error: %s", e, exc_info=True)
            await updater.update_status(TaskState.failed, new_agent_text_message(f"Error: {e}"))

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Attacker Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9021, help="Port to bind to")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="attacker",
        description="Red team attacker for security testing",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = Attacker(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting Attacker on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
