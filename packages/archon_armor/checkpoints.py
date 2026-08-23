"""Battle checkpoint/resume — survive interrupted long-running campaigns.

`BattleManager.execute(checkpoint_path=...)` persists the verdict list after
every probe, so a crashed or killed campaign loses at most one probe of work.
Re-invoking with `resume_state=<loaded checkpoint>` skips already-completed
probes and finalizes with the merged results.
"""

from __future__ import annotations

import json
from pathlib import Path


def _write_checkpoint(
    path: str,
    battle_id: str,
    agent_id: str,
    results: list[dict],
    pending: list[str],
) -> None:
    payload = {
        "battle_id": battle_id,
        "agent_id": agent_id,
        "results": results,
        "pending": pending,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload))
    tmp.replace(target)


def load_checkpoint(path: str) -> dict | None:
    source = Path(path)
    if not source.exists():
        return None
    return json.loads(source.read_text())
