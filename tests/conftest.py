"""Test configuration for AgentBeats Security Arena tests."""

import sys
from pathlib import Path

# Add the scenarios directory to Python path for imports
_scenarios_root = Path(__file__).parent.parent / "scenarios"
if str(_scenarios_root) not in sys.path:
    sys.path.insert(0, str(_scenarios_root))
