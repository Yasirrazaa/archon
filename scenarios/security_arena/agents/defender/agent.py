#!/usr/bin/env python3
"""
Defender Agent - Processes inputs and performs assigned tasks.

Receives filtered scenario context as JSON (no attack info), builds dynamic prompts,
and processes formatted input according to the scenario using a 4-Layer Defense Pipeline.
"""

import argparse
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

from openai import AsyncOpenAI

# Load custom defense modules
import sys
sys.path.append(str(Path(__file__).parent))
import pyrit_defense

# Load templates
_template_dir = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_template_dir), trim_blocks=True, lstrip_blocks=True)
_system_template = _env.get_template("system.j2")
_user_template = _env.get_template("user.j2")
_classifier_template = _env.get_template("exchange_classifier.j2")

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
logger = logging.getLogger("defender")


@dataclass
class ScenarioContext:
    """Filtered scenario context from orchestrator (no attack info)."""
    domain_description: str   # Domain/system description
    defender_role: str        # Defender's role description
    defender_task: str        # What defender should do
    output_format: str        # Expected output format
    formatted_input: str      # Input to process

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioContext":
        return cls(
            domain_description=d.get("domain_description", ""),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            output_format=d.get("output_format", ""),
            formatted_input=d.get("formatted_input", ""),
        )


class Defender(AgentExecutor):
    """Defender that processes inputs according to scenario context with SOTA pipeline."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL")
        )
        self.model = model

    def _render(self, template, **kwargs) -> str:
        """Render a Jinja2 template."""
        return template.render(**kwargs)

    async def _generate(self, system: str, user: str, temperature: float = 0.1, response_format=None) -> str:
        """Generate a response from the LLM."""
        kwargs = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": temperature
        }
        if response_format:
            kwargs["response_format"] = response_format
            
        response = await self.client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content
        return content if content is not None else ""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Process input based on scenario context using the 4-layer pipeline."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            # Parse JSON context
            message_text = context.get_user_input()
            ctx = ScenarioContext.from_dict(json.loads(message_text))
            task_id = str(task.id)
            
            logger.info("Processing task: %s...", ctx.defender_task[:50])

            # ---------------------------------------------------------
            # LAYER 0: Pure Python Sanitization (0 LLM Calls)
            # ---------------------------------------------------------
            sanitized_input = pyrit_defense.layer0_sanitize_input(ctx.formatted_input)
            
            # ---------------------------------------------------------
            # LAYER 1: Adaptive First Call (Paraphrase) (1 LLM Call)
            # ---------------------------------------------------------
            # To save budget and reduce false positives, we always try to paraphrase 
            # the input to destroy formatting attacks while keeping semantics.
            combined_context = (ctx.domain_description + " " + ctx.defender_task).lower()
            is_conversational = "shopping assistant" in combined_context or "thingularity" in combined_context
            
            paraphrase_prompt = pyrit_defense.layer1_adversarial_paraphrase_prompt(sanitized_input, is_conversational)
            paraphrased_input = await self._generate(
                system="You are a helpful text summarizer. Follow the user's instructions exactly.",
                user=paraphrase_prompt,
                temperature=0.0
            )
            
            # ---------------------------------------------------------
            # LAYER 2: Spotlighting + PPA (0 LLM Calls)
            # ---------------------------------------------------------
            wrapped_input = pyrit_defense.layer2_spotlighting_wrap(paraphrased_input, task_id, is_conversational)
            
            # ---------------------------------------------------------
            # LAYER 3: Task Shield Generation (1 LLM Call)
            # ---------------------------------------------------------
            invariants = pyrit_defense.get_scenario_invariants(ctx.domain_description, ctx.defender_task)
            
            system_prompt = self._render(_system_template, 
                                         defender_role=ctx.defender_role,
                                         domain_description=ctx.domain_description,
                                         defender_task=ctx.defender_task,
                                         output_format=ctx.output_format,
                                         invariants=invariants)
                                         
            user_prompt = self._render(_user_template, processed_input=wrapped_input)
            
            candidate_response = await self._generate(system_prompt, user_prompt, temperature=0.1)
            
            # ---------------------------------------------------------
            # LAYER 4: CC++ Exchange Classifier (1 LLM Call)
            # ---------------------------------------------------------
            # Classify the (original sanitized input, candidate response) pair
            classifier_prompt = self._render(_classifier_template,
                                             defender_task=ctx.defender_task,
                                             invariants=invariants,
                                             user_input=sanitized_input,
                                             candidate_response=candidate_response)
                                             
            classifier_result = await self._generate(
                system="You are a strict security classifier. Return only valid JSON.",
                user=classifier_prompt,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            
            try:
                eval_data = json.loads(classifier_result)
                is_safe = eval_data.get("exchange_safe", True)
                confidence = eval_data.get("confidence", 0.0)
                
                # If unsafe with high confidence, trigger safety fallback
                if not is_safe and confidence > 0.85:
                    logger.warning("Exchange classifier blocked response! Violation: %s", eval_data.get("violation_type"))
                    # Fallback to generic safe response in the requested format
                    safe_fallback = f"Unable to process request due to safety invariant violation. Please revise your query to align with the task: {ctx.defender_task}"
                    
                    # Call 4: Try to format the fallback into the required output format
                    fallback_system = f"You must format the provided text EXACTLY according to this format: {ctx.output_format}. Do not add any other text."
                    candidate_response = await self._generate(fallback_system, safe_fallback, temperature=0.0)
            except json.JSONDecodeError:
                logger.error("Failed to parse exchange classifier JSON, proceeding with candidate response.")

            logger.info("Generated final response (%d chars)", len(candidate_response))
            await updater.update_status(TaskState.completed, new_agent_text_message(candidate_response))
            
        except Exception as e:
            logger.error("Defender error: %s", e, exc_info=True)
            await updater.update_status(TaskState.failed, new_agent_text_message(f"Error: {e}"))

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Defender Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9020, help="Port to bind to")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="defender",
        description="Defender agent that processes inputs according to role",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = Defender(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting Defender on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
