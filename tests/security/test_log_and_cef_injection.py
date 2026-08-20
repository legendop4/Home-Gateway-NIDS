"""
Security Tests: Log Injection and CEF Field Corruption Prevention.
Verifies attacker-controlled values cannot inject newlines, ANSI escape sequences, or break CEF structure.
"""

import pytest
from nids.storage.models import AlertRecord
from nids.storage.exporter import SiemExporter
from nids.security.sanitization import sanitize_for_log, sanitize_for_cef


def test_log_injection_crlf_and_ansi_stripped():
    malicious_input = "192.168.1.1\n[2026-08-19 ERROR] Fake forged log line\r\n\x1B[31mRedText\x1B[0m"
    sanitized = sanitize_for_log(malicious_input)

    assert "\n" not in sanitized
    assert "\r" not in sanitized
    assert "\x1B" not in sanitized
    assert "RedText" in sanitized


def test_cef_field_injection_escaped(tmp_path):
    exporter = SiemExporter(export_file_path=str(tmp_path / "cef_test.jsonl"))

    alert = AlertRecord(
        timestamp=1700000000.0,
        iso_timestamp="2026-08-19T12:00:00Z",
        src_ip="192.168.1.100|cs1=INJECTED_FIELD",
        dst_ip="10.0.0.1\nmalicious_line",
        attack_family="Reconnaissance|Critical=10",
        detection_method="HYBRID",
        confidence_score=0.99,
        suricata_signature="ET SCAN Test|malicious=true",
        suricata_sid=2000001,
        ml_status="ACTIVE",
        details="Attack details | dangerous=yes = 1 \nnewline",
    )

    cef_output = exporter.to_cef(alert)

    # Pipes and equals within data fields must be escaped as \| and \=
    assert "192.168.1.100\\|cs1\\=INJECTED_FIELD" in cef_output
    assert "Reconnaissance\\|Critical\\=10" in cef_output
    # Must be a single contiguous line (no raw \n)
    assert "\n" not in cef_output
