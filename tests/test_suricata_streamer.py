"""
Unit tests for SuricataEveStreamer, JSON parsing, and recon alert filtering.
"""

import json
import pytest
from nids.capture.eve_streamer import SuricataEveStreamer, SuricataEvent


def test_suricata_eve_parsing_recon_alert():
    streamer = SuricataEveStreamer()
    recon_json = json.dumps({
        "timestamp": "2026-08-19T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "192.168.1.1",
        "src_port": 54321,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": "ET SCAN Potential Nmap SYN Scan",
            "category": "Attempted Information Leak",
            "severity": 2
        }
    })

    event = streamer.parse_event(recon_json)
    assert event is not None
    assert event.src_ip == "192.168.1.100"
    assert event.dst_ip == "192.168.1.1"
    assert event.signature_id == 2000001
    assert "Nmap" in event.signature
    assert event.severity == 2


def test_suricata_eve_filter_non_recon():
    streamer = SuricataEveStreamer()
    non_recon_json = json.dumps({
        "timestamp": "2026-08-19T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "192.168.1.1",
        "alert": {
            "signature": "GPL DNS named version attempt",
            "category": "Misc Attack",
            "severity": 3
        }
    })
    event = streamer.parse_event(non_recon_json)
    assert event is None


def test_suricata_eve_filter_flow_event():
    streamer = SuricataEveStreamer()
    flow_json = json.dumps({
        "timestamp": "2026-08-19T12:00:00.000000+0000",
        "event_type": "flow",
        "src_ip": "192.168.1.100",
        "dest_ip": "192.168.1.1"
    })
    event = streamer.parse_event(flow_json)
    assert event is None
