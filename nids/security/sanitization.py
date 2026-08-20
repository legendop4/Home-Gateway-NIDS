"""
Input validation and log/CEF/path sanitization routines for Home-Gateway NIDS.
Defends against:
- Log injection / CRLF injection
- Path traversal
- SQL injection / malformed input
- SIEM / CEF field corruption
"""

from pathlib import Path
import ipaddress
import re
from typing import Optional, Tuple, Any


def validate_ip_address(ip_str: str) -> bool:
    """Validates that a string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_pagination(
    limit: Any,
    offset: Any,
    default_limit: int = 50,
    max_limit: int = 100,
) -> Tuple[int, int]:
    """
    Validates and bounds pagination parameters.
    Raises ValueError on negative, non-integer, or malformed inputs.
    """
    try:
        lim = int(limit) if limit is not None else default_limit
        off = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        raise ValueError("Pagination limit and offset must be valid integers.")

    if lim < 1:
        raise ValueError("Limit must be at least 1.")
    if lim > max_limit:
        lim = max_limit

    if off < 0:
        raise ValueError("Offset cannot be negative.")
    if off > 1000000:
        raise ValueError("Offset exceeds maximum allowed depth.")

    return lim, off


def validate_integer_id(id_val: Any, field_name: str = "id") -> int:
    """Validates that an ID parameter is a positive integer."""
    try:
        val = int(id_val)
    except (ValueError, TypeError):
        raise ValueError(f"{field_name} must be a valid integer.")
    if val < 1:
        raise ValueError(f"{field_name} must be greater than 0.")
    return val


def sanitize_for_log(value: Any) -> str:
    """
    Removes CRLF and ANSI escape sequences to prevent log injection and terminal poisoning.
    """
    if value is None:
        return ""
    val_str = str(value)
    # Strip ANSI escape sequences
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    cleaned = ansi_escape.sub("", val_str)
    # Replace CRLF / control chars with whitespace
    cleaned = cleaned.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return cleaned.strip()


def sanitize_for_cef(value: Any) -> str:
    r"""
    Escapes special CEF characters according to ArcSight CEF specifications:
    - Backslash \ -> \\
    - Pipe | -> \|
    - Equals = -> \=
    - Newlines \n / \r -> escaped space
    """
    if value is None:
        return ""
    val_str = str(value)
    # First escape backslashes
    val_str = val_str.replace("\\", "\\\\")
    # Escape pipes and equals
    val_str = val_str.replace("|", "\\|").replace("=", "\\=")
    # Remove raw newlines
    val_str = val_str.replace("\r", " ").replace("\n", " ")
    return val_str.strip()


import urllib.parse


def resolve_safe_path(base_dir: str, target_filename: str) -> Path:
    """
    Resolves a filesystem path and strictly ensures it cannot escape base_dir.
    Raises ValueError if path traversal is detected.
    """
    base = Path(base_dir).resolve()
    # Decode URL-encoded characters (e.g. %2e%2e%2f -> ../)
    decoded_filename = urllib.parse.unquote(target_filename)

    # Reject explicit path traversal tokens in filename
    if ".." in decoded_filename or "/" in decoded_filename or "\\" in decoded_filename or ":" in decoded_filename:
        raise ValueError("Invalid filename: Path traversal characters are not permitted.")

    target = (base / decoded_filename).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise ValueError("Path traversal attempt detected.")

    return target
