"""Scenario plugin system for Security Arena"""

from .base import ScenarioPlugin
from .example_medical import MedicalRecordsPlugin
from .portfolioiq import PortfolioIQPlugin
from .registry import list_scenarios, load_scenario, register_scenario
from .thingularity import ThingularityPlugin

__all__ = [
    "ScenarioPlugin",
    "load_scenario",
    "list_scenarios",
    "register_scenario",
    "PortfolioIQPlugin",
    "ThingularityPlugin",
    "MedicalRecordsPlugin",
]
