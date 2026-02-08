import secrets
from datetime import datetime
from pathlib import Path

from flask import Blueprint, g, jsonify, request, send_file

from common.observability.metrics import create_counter
from common.schemas.alerts import AlertCreate  # noqa: E402
from controller.export_engine import ReportData, ReportEngine, ReportFormat, ReportType
from controller.models import Alert
from controller.tasks import process_alert

from .auth import Permission, require_auth, require_signed
from .deps import PYDANTIC_AVAILABLE, config, limiter, logger, validate_json

bp = Blueprint("alerts", __name__)

ALERTS_EMITTED = create_counter(
    "alerts_emitted_total", "Alerts emissions", ["severity", "detector"]
)


@bp.route("/alerts", methods=["POST"])
@require_auth(Permission.WRITE_ALERTS)
@require_signed()
@limiter.limit(config.security.rate_limit_alerts)
@validate_json(AlertCreate) if PYDANTIC_AVAILABLE else lambda f: f
def create_alert():
    if PYDANTIC_AVAILABLE and hasattr(g, "validated_data"):
        if hasattr(g.validated_data, "model_dump"):
            data = g.validated_data.model_dump(mode="json")
        else:
            data = g.validated_data.dict()
    else:
        data = request.get_json()

    alert_id = secrets.token_hex(8)

    # Prepare data for worker
    alert_payload = {
        "id": alert_id,
        "alert_type": data.get("alert_type"),
        "severity": data.get("severity"),
        "title": data.get("title"),
        "description": data.get("description"),
        "evidence": data.get("evidence"),
    }

    try:
        process_alert.delay(alert_payload, g.token.sensor_id)

        # We assume accepted for metrics here, or let worker handle it.
        # Original code incremented ALERTS_EMITTED here.
        # We can increment "alert_requests_accepted" if we had that metric.
        # But ALERTS_EMITTED is "emitted" so maybe keeping it here is misleading if it fails processing.
        # Let's rely on worker metric.

        return jsonify(
            {"success": True, "alert_id": alert_id, "status": "accepted"}
        ), 202

    except Exception as e:
        logger.error(f"Failed to enqueue alert: {e}")
        return jsonify({"error": "Internal processing error"}), 500


@bp.route("/alerts", methods=["GET"])
@require_auth(Permission.READ_ALERTS)
def get_alerts():
    limit = min(int(request.args.get("limit", 50)), 500)
    severity = request.args.get("severity")

    query = Alert.query.order_by(Alert.created_at.desc())
    if severity:
        query = query.filter_by(severity=severity)

    records = query.limit(limit).all()

    # Serialize
    results = []
    for r in records:
        results.append(
            {
                "id": r.id,
                "sensor_id": r.sensor_id,
                "title": r.title,
                "severity": r.severity,
                "created_at": r.created_at.isoformat(),
                "description": r.description,
            }
        )

    return jsonify({"count": len(results), "items": results})


@bp.route("/reports/generate", methods=["POST"])
@require_auth(Permission.READ_ALERTS)
@limiter.limit("10 per minute")
def generate_remote_report():
    """Generate report from provided data"""
    data = request.get_json()

    try:
        report_info = data.get("report", {})
        summary = data.get("summary", {})
        findings = data.get("findings", [])
        actions = data.get("actions", [])

        # Transform findings from Audit format to Report format
        report_findings = []
        for f in findings:
            report_findings.append(
                {
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "severity": f.get("severity", "medium").lower(),
                }
            )

        report_data = ReportData(
            report_type=ReportType.AUDIT,
            title=report_info.get("title", "Security Scan"),
            generated_at=report_info.get("date", datetime.now().isoformat()),
            total_networks=summary.get("networks_scanned", 0),
            critical_risks=summary.get("counts", {}).get("critical", 0),
            high_risks=summary.get("counts", {}).get("high", 0),
            medium_risks=summary.get("counts", {}).get("medium", 0),
            total_alerts=len(findings),
            sensors_active=1,
            findings=report_findings,
            recommendations=[a.get("task") for a in actions],
        )

        engine = ReportEngine(output_dir=Path("./generated_reports"))
        # Prefer PDF if available
        format = ReportFormat.PDF

        output_path = engine.generate(report_data, format)

        return send_file(
            output_path,
            mimetype="application/pdf" if format == ReportFormat.PDF else "text/html",
            as_attachment=True,
            download_name=output_path.name,
        )

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({"error": str(e)}), 500
