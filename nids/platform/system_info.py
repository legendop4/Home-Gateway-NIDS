"""
System Telemetry: Collects CPU, RAM, disk, and platform status.
"""

from typing import Dict, Any
import os
import platform
import time

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def get_system_telemetry() -> Dict[str, Any]:
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "timestamp": time.time(),
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "memory_used_mb": 0.0,
    }

    if PSUTIL_AVAILABLE:
        try:
            info["cpu_percent"] = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            info["memory_percent"] = mem.percent
            info["memory_used_mb"] = round(mem.used / (1024 * 1024), 1)
        except Exception:
            pass

    return info
