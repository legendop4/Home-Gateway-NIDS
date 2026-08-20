"""
Security Middleware for Flask: Security Headers, CORS, and Production Error Masking.
"""

from typing import Optional, List
from flask import Flask, Response, request, jsonify
import logging

logger = logging.getLogger("nids.security")


def setup_security_middleware(app: Flask, config: Optional[dict] = None) -> None:
    """
    Attaches security headers, CORS restrictions, and error handlers to the Flask application.
    """
    sec_cfg = (config or {}).get("security", {})
    allowed_origins = sec_cfg.get("allowed_origins", ["http://127.0.0.1:5000", "http://localhost:5000"])

    # Bound maximum request body size (1 MB max payload)
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        # Standard OWASP security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy (allows local assets, Google Fonts, and Chart.js / FontAwesome CDNs used by SOC dashboard)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )

        # Cache-Control for sensitive API endpoints
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        # CORS Handling
        origin = request.headers.get("Origin")
        if origin:
            if origin in allowed_origins or "*" in allowed_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization"
                response.headers["Access-Control-Allow-Credentials"] = "true"

        return response

    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({"error": "Bad Request: Malformed or invalid input parameters.", "status_code": 400}), 400

    @app.errorhandler(401)
    def handle_unauthorized(e):
        return jsonify({"error": "Unauthorized: Authentication credentials required.", "status_code": 401}), 401

    @app.errorhandler(403)
    def handle_forbidden(e):
        return jsonify({"error": "Forbidden: Insufficient privileges.", "status_code": 403}), 403

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({"error": "Not Found: The requested resource does not exist.", "status_code": 404}), 404

    @app.errorhandler(413)
    def handle_payload_too_large(e):
        return jsonify({"error": "Payload Too Large: Request body exceeds maximum allowed size (1MB).", "status_code": 413}), 413

    @app.errorhandler(429)
    def handle_rate_limit(e):
        return jsonify({"error": "Too Many Requests: Rate limit exceeded.", "status_code": 429}), 429

    @app.errorhandler(500)
    def handle_internal_server_error(e):
        logger.error(f"[SecurityMiddleware] Internal error during request {request.path}: {e}", exc_info=True)
        # Never expose internal Python traceback or filesystem paths to API client
        return jsonify({"error": "Internal Server Error: An unexpected error occurred.", "status_code": 500}), 500
