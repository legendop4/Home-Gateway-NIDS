"""
Platform-Specific Adapters Package for Home-Gateway NIDS.
"""

from .system_info import get_system_telemetry
from .pi_adapter import RaspberryPiAdapter

__all__ = ["get_system_telemetry", "RaspberryPiAdapter"]
