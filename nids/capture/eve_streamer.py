"""
Suricata EVE JSON streamer and parser.
Tails eve.json and extracts reconnaissance / port-scan alerts.
"""

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional
import json
import time
import threading


@dataclass
class SuricataEvent:
    timestamp: float
    iso_timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    event_type: str
    signature: str
    signature_id: int
    category: str
    severity: int  # 1 = high, 2 = medium, 3 = low
    raw_event: Dict


class SuricataEveStreamer:
    """
    Tails a Suricata eve.json log file and streams filtered reconnaissance alerts.
    """

    def __init__(
        self,
        eve_path: str = "data/eve.json",
        recon_keywords: Optional[List[str]] = None,
        poll_interval_sec: float = 0.5,
    ):
        self.eve_path = Path(eve_path)
        self.recon_keywords = [
            k.lower() for k in (recon_keywords or [
                "scan", "portscan", "nmap", "reconnaissance",
                "ssh scan", "syn scan", "fin scan", "null scan", "xmas scan"
            ])
        ]
        self.poll_interval_sec = poll_interval_sec
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_file_pos = 0

    def is_recon_alert(self, event: Dict) -> bool:
        if event.get("event_type") != "alert":
            return False
        alert = event.get("alert", {})
        signature = alert.get("signature", "").lower()
        category = alert.get("category", "").lower()

        for kw in self.recon_keywords:
            if kw in signature or kw in category:
                return True
        return False

    def parse_event(self, line: str) -> Optional[SuricataEvent]:
        try:
            raw = json.loads(line.strip())
            if not self.is_recon_alert(raw):
                return None

            alert = raw.get("alert", {})
            ts_str = raw.get("timestamp", "")
            # Convert ISO 8601 or fallback to current timestamp
            ts = time.time()

            return SuricataEvent(
                timestamp=ts,
                iso_timestamp=ts_str,
                src_ip=raw.get("src_ip", ""),
                dst_ip=raw.get("dest_ip", ""),
                src_port=int(raw.get("src_port", 0) or 0),
                dst_port=int(raw.get("dest_port", 0) or 0),
                protocol=raw.get("proto", "TCP"),
                event_type=raw.get("event_type", "alert"),
                signature=alert.get("signature", "Unknown Scan Signature"),
                signature_id=int(alert.get("signature_id", 0)),
                category=alert.get("category", "Attempted Information Leak"),
                severity=int(alert.get("severity", 3)),
                raw_event=raw,
            )
        except Exception:
            return None

    def start(self, callback: Callable[[SuricataEvent], None]) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._tail_loop, args=(callback,), daemon=True)
        self._thread.start()

    def _tail_loop(self, callback: Callable[[SuricataEvent], None]) -> None:
        while self._running:
            if not self.eve_path.exists():
                time.sleep(self.poll_interval_sec)
                continue

            try:
                with open(self.eve_path, "r", encoding="utf-8") as f:
                    # Seek to previous position if file didn't truncate
                    if self._last_file_pos > 0 and self.eve_path.stat().st_size >= self._last_file_pos:
                        f.seek(self._last_file_pos)
                    else:
                        # File was rotated/created fresh
                        f.seek(0)

                    while self._running:
                        line = f.readline()
                        if not line:
                            self._last_file_pos = f.tell()
                            time.sleep(self.poll_interval_sec)
                            # Check if file size shrank (rotation)
                            if self.eve_path.stat().st_size < self._last_file_pos:
                                break
                            continue

                        parsed = self.parse_event(line)
                        if parsed:
                            callback(parsed)
            except Exception as e:
                time.sleep(self.poll_interval_sec)

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
