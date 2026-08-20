"""
Raspberry Pi Specific Platform Adapter.
Handles hostapd, dnsmasq, iptables NAT validation, and service checks.
"""

from typing import Dict, Any
import subprocess
import os
import platform


class RaspberryPiAdapter:
    """
    Platform adapter for Raspberry Pi OS gateway environments.
    """

    @staticmethod
    def is_raspberry_pi() -> bool:
        if platform.system().lower() != "linux":
            return False
        try:
            with open("/proc/cpuinfo", "r") as f:
                content = f.read().lower()
                return "raspberry pi" in content or "bcm" in content
        except Exception:
            return False

    @staticmethod
    def check_service_status(service_name: str) -> str:
        """Check systemd unit status."""
        if platform.system().lower() != "linux":
            return "UNSUPPORTED_OS"
        try:
            res = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=2,
            )
            return res.stdout.strip()
        except Exception:
            return "UNKNOWN"

    @staticmethod
    def get_gateway_status() -> Dict[str, Any]:
        return {
            "is_pi": RaspberryPiAdapter.is_raspberry_pi(),
            "hostapd_status": RaspberryPiAdapter.check_service_status("hostapd"),
            "dnsmasq_status": RaspberryPiAdapter.check_service_status("dnsmasq"),
            "suricata_status": RaspberryPiAdapter.check_service_status("suricata"),
        }
