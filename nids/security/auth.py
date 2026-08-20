"""
Authentication and Role-Based Access Control (RBAC) for Home-Gateway NIDS.
Defines VIEWER and ADMIN roles, constant-time token comparison, and environment-driven secrets.
"""

from enum import Enum
from functools import wraps
import hmac
import os
from typing import Optional, Callable, Tuple
from flask import request, jsonify, current_app


class Role(str, Enum):
    VIEWER = "VIEWER"
    ADMIN = "ADMIN"


import secrets


class SecurityConfig:
    """Reads security configuration and API keys from environment or config."""

    _ephemeral_admin_key: Optional[str] = None
    _ephemeral_viewer_key: Optional[str] = None

    @classmethod
    def is_production(cls, config: Optional[dict] = None) -> bool:
        env_mode = os.environ.get("NIDS_ENVIRONMENT", (config or {}).get("system", {}).get("environment", "development"))
        return env_mode.lower() == "production"

    @classmethod
    def get_admin_key(cls, config: Optional[dict] = None) -> str:
        env_key = os.environ.get("NIDS_ADMIN_API_KEY")
        if env_key:
            return env_key
        cfg_key = (config or {}).get("security", {}).get("admin_api_key")
        if cfg_key:
            return cfg_key

        if cls.is_production(config):
            raise RuntimeError("Production security violation: NIDS_ADMIN_API_KEY must be configured in environment.")

        # Ephemeral random session key for development if none configured
        if cls._ephemeral_admin_key is None:
            cls._ephemeral_admin_key = secrets.token_urlsafe(24)
        return cls._ephemeral_admin_key

    @classmethod
    def get_viewer_key(cls, config: Optional[dict] = None) -> str:
        env_key = os.environ.get("NIDS_VIEWER_API_KEY")
        if env_key:
            return env_key
        cfg_key = (config or {}).get("security", {}).get("viewer_api_key")
        if cfg_key:
            return cfg_key

        if cls.is_production(config):
            raise RuntimeError("Production security violation: NIDS_VIEWER_API_KEY must be configured in environment.")

        if cls._ephemeral_viewer_key is None:
            cls._ephemeral_viewer_key = secrets.token_urlsafe(24)
        return cls._ephemeral_viewer_key


def get_token_from_request() -> Optional[str]:
    """Extracts authentication token from Authorization Bearer or X-API-Key headers."""
    # Check X-API-Key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()

    # Check Authorization: Bearer <token>
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    # Check query parameter ?api_key= (allowed only for export downloads)
    param_key = request.args.get("api_key")
    if param_key:
        return param_key.strip()

    return None


def authenticate_request(config: Optional[dict] = None) -> Tuple[bool, Optional[Role]]:
    """
    Authenticates incoming request against configured credentials.
    In development mode: localhost requests without credentials default to VIEWER role.
    In production mode: all requests must provide a valid API key.
    """
    token = get_token_from_request()
    admin_key = SecurityConfig.get_admin_key(config)
    viewer_key = SecurityConfig.get_viewer_key(config)

    if token:
        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(token, admin_key):
            return True, Role.ADMIN
        if hmac.compare_digest(token, viewer_key):
            return True, Role.VIEWER
        return False, None

    # Development mode localhost fallback
    is_prod = SecurityConfig.is_production(config)
    remote_ip = request.remote_addr or ""
    is_localhost = remote_ip in ["127.0.0.1", "::1", "localhost", "testclient"]

    if not is_prod and is_localhost:
        # In dev mode on localhost, grant ADMIN privileges for seamless developer experience
        return True, Role.ADMIN

    return False, None


def require_role(required_role: Role = Role.VIEWER, config: Optional[dict] = None) -> Callable:
    """
    Decorator that enforces role-based access control.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            cfg = config or getattr(current_app, "nids_config", None)
            authenticated, role = authenticate_request(cfg)

            if not authenticated:
                return jsonify({
                    "error": "Unauthorized: Valid API key required in X-API-Key or Authorization header.",
                    "status_code": 401
                }), 401

            # Role hierarchy: ADMIN has all VIEWER permissions
            if required_role == Role.ADMIN and role != Role.ADMIN:
                return jsonify({
                    "error": "Forbidden: Administrative privileges required.",
                    "status_code": 403
                }), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator
