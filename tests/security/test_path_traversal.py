"""
Security Tests: Path Traversal Defenses.
Verifies resolve_safe_path and file export endpoints strictly reject path traversal payloads.
"""

import pytest
from pathlib import Path
from nids.security.sanitization import resolve_safe_path


def test_resolve_safe_path_valid(tmp_path):
    base_dir = tmp_path / "data"
    base_dir.mkdir()
    target_file = base_dir / "valid_log.jsonl"
    target_file.touch()

    resolved = resolve_safe_path(str(base_dir), "valid_log.jsonl")
    assert resolved == target_file.resolve()


def test_resolve_safe_path_traversal_payloads(tmp_path):
    base_dir = tmp_path / "data"
    base_dir.mkdir()

    traversal_payloads = [
        "../../../../etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e%2fetc%2fpasswd",
        "nested/../../secret.key",
        "/etc/shadow",
        "C:\\boot.ini",
    ]

    for payload in traversal_payloads:
        with pytest.raises(ValueError):
            resolve_safe_path(str(base_dir), payload)
