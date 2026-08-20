"""
Hardened Flask Web API and Static Route Provider for Home-Gateway NIDS.
Includes RBAC authentication, input validation, rate limiting, security headers, and safe error masking.
"""

from pathlib import Path
from typing import Optional
from flask import Flask, jsonify, render_template, request, send_file
import time
import os

from ..storage.database import NidsDatabase
from ..ml.transformer_model import TransformerInferenceEngine
from ..feature_extraction.window_sequencer import WindowSequencer
from ..security import (
    Role,
    require_role,
    rate_limit,
    validate_ip_address,
    validate_pagination,
    validate_integer_id,
    resolve_safe_path,
    setup_security_middleware,
)


def create_dashboard_app(
    db: NidsDatabase,
    ml_engine: Optional[TransformerInferenceEngine] = None,
    sequencer: Optional[WindowSequencer] = None,
    config: Optional[dict] = None,
) -> Flask:
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.nids_config = config or {}

    # Attach OWASP security headers, CORS, body limits, and safe error handlers
    setup_security_middleware(app, config)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/stats")
    @rate_limit(requests_per_minute=120)
    @require_role(Role.VIEWER)
    def get_stats():
        summary = db.get_stats_summary()
        ml_status = "ACTIVE" if (ml_engine and ml_engine.is_available) else "ML_UNAVAILABLE"
        summary["ml_status"] = ml_status
        summary["server_time"] = time.time()
        summary["environment"] = (config or {}).get("system", {}).get("environment", "development")
        return jsonify(summary)

    @app.route("/api/alerts")
    @rate_limit(requests_per_minute=120)
    @require_role(Role.VIEWER)
    def get_alerts():
        try:
            limit, offset = validate_pagination(
                request.args.get("limit"),
                request.args.get("offset"),
                default_limit=50,
                max_limit=100,
            )
        except ValueError as e:
            return jsonify({"error": f"Invalid pagination: {e}", "status_code": 400}), 400

        alerts = db.get_recent_alerts(limit=limit, offset=offset)
        return jsonify({"alerts": alerts, "count": len(alerts)})

    @app.route("/api/devices")
    @rate_limit(requests_per_minute=120)
    @require_role(Role.VIEWER)
    def get_devices():
        devices = db.get_all_devices()
        return jsonify({"devices": devices, "count": len(devices)})

    @app.route("/api/metrics")
    @rate_limit(requests_per_minute=120)
    @require_role(Role.VIEWER)
    def get_metrics():
        try:
            limit, _ = validate_pagination(
                request.args.get("limit"),
                offset=0,
                default_limit=60,
                max_limit=120,
            )
        except ValueError as e:
            return jsonify({"error": f"Invalid limit parameter: {e}", "status_code": 400}), 400

        metrics = db.get_recent_metrics(limit=limit)
        return jsonify({"metrics": metrics, "count": len(metrics)})

    @app.route("/api/sequence/<src_ip>")
    @rate_limit(requests_per_minute=60)
    @require_role(Role.VIEWER)
    def get_ip_sequence(src_ip: str):
        # Strict IP validation to prevent injection or invalid lookups
        if not validate_ip_address(src_ip):
            return jsonify({"error": "Invalid IP address format.", "status_code": 400}), 400

        if sequencer is None:
            return jsonify({"error": "Sequencer not attached.", "status_code": 503}), 503

        seq, mask = sequencer.get_sequence_tensor(src_ip, include_active=True)
        ml_score = 0.0
        ml_status = "ACTIVE"
        if ml_engine and ml_engine.is_available:
            try:
                ml_score = ml_engine.predict_score(seq, mask)
            except Exception:
                ml_status = "ML_UNAVAILABLE"
        else:
            ml_status = "ML_UNAVAILABLE"

        feature_names = [
            "dst_port_count", "dst_ip_count", "syn_ratio", "syn_ack_ratio",
            "rst_ratio", "packet_rate", "byte_rate", "flow_duration_mean"
        ]
        sequence_data = []
        for t in range(len(seq)):
            step_dict = {
                "step": t + 1,
                "is_valid": bool(mask[t] > 0),
                "features": {name: float(round(seq[t, i], 4)) for i, name in enumerate(feature_names)}
            }
            sequence_data.append(step_dict)

        return jsonify({
            "src_ip": src_ip,
            "ml_status": ml_status,
            "anomaly_score": float(round(ml_score, 4)),
            "sequence": sequence_data,
        })

    @app.route("/api/health")
    @rate_limit(requests_per_minute=120)
    @require_role(Role.VIEWER)
    def get_health():
        from ..health import get_health_manager
        mgr = get_health_manager()
        mgr.heartbeat("dashboard_api", {"last_request_path": request.path})
        return jsonify(mgr.get_system_health())

    @app.route("/api/siem/export")
    @rate_limit(requests_per_minute=15)
    @require_role(Role.ADMIN)
    def export_siem():
        configured_path = (config or {}).get("system", {}).get("siem_export_path", "data/siem_alerts.jsonl")
        export_file = Path(configured_path)
        
        # Defend against path traversal: ensure export target is canonically inside data/
        try:
            safe_file = resolve_safe_path(str(export_file.parent), export_file.name)
        except ValueError as e:
            return jsonify({"error": f"Path validation failed: {e}", "status_code": 400}), 400

        if not safe_file.exists():
            return jsonify({"error": "No SIEM export logs generated yet.", "status_code": 404}), 404

        return send_file(str(safe_file), as_attachment=True, download_name="siem_alerts.jsonl")

    return app
