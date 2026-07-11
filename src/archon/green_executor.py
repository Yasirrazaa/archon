from abc import abstractmethod
from contextlib import suppress

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import (
    InternalError,
    InvalidParamsError,
    TaskState,
    UnsupportedOperationError,
)
from a2a.utils import (
    new_agent_text_message,
    new_task,
)
from a2a.utils.errors import ServerError
from pydantic import ValidationError

from archon.models import EvalRequest


class GreenAgent:

    @abstractmethod
    async def run_eval(self, request: EvalRequest, updater: TaskUpdater) -> None:
        pass

    @abstractmethod
    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        pass


class GreenExecutor(AgentExecutor):

    def __init__(self, green_agent: GreenAgent):
        self.agent = green_agent

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        request_text = context.get_user_input()
        try:
            req: EvalRequest = EvalRequest.model_validate_json(request_text)
            ok, msg = self.agent.validate_request(req)
            if not ok:
                raise ServerError(error=InvalidParamsError(message=msg)) from None
        except ValidationError as e:
            raise ServerError(error=InvalidParamsError(message=e.json())) from e

        msg_obj = context.message
        if msg_obj:
            task = new_task(msg_obj)
            await event_queue.enqueue_event(task)
        else:
            raise ServerError(error=InvalidParamsError(message="Missing message.")) from None

        updater = TaskUpdater(event_queue, task.id, task.context_id)
        await updater.update_status(
            TaskState.working,
            new_agent_text_message(f"Starting assessment.\n{req.model_dump_json()}", context_id=context.context_id)
        )

        try:
            await self.agent.run_eval(req, updater)
            # Only complete if not already in terminal state (agent may have called complete/failed)
            with suppress(RuntimeError):
                await updater.complete()
        except Exception as e:
            with suppress(RuntimeError):
                await updater.failed(new_agent_text_message(f"Agent error: {e}", context_id=context.context_id))
            raise ServerError(error=InternalError(message=str(e))) from e

    async def cancel(
        self, request: RequestContext, event_queue: EventQueue
    ) -> None:
        raise ServerError(error=UnsupportedOperationError()) from None
