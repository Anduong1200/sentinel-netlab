import secrets
from datetime import datetime
from pathlib import Path

from flask import Blueprint, g, jsonify, request, send_file

from common.schemas.alerts import AlertCreate  # noqa: E402
from controller.export_engine import ReportData, ReportEngine, ReportFormat, ReportType

from .auth import Permission, require_auth, require_signed
from .deps import PYDANTIC_AVAILABLE, config, db, limiter, logger, validate_json
from .models import DBAlert

bp = Blueprint("alerts", __name__)


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

    alert = DBAlert(
        id=secrets.token_hex(8),
        sensor_id=g.token.sensor_id,
        alert_type=data.get("alert_type"),
        severity=data.get("severity"),
        title=data.get("title"),
        description=data.get("description"),
        evidence=data.get("evidence"),
    )

    db.session.add(alert)
    db.session.commit()

    return jsonify({"success": True, "alert_id": alert.id})


@bp.route("/alerts", methods=["GET"])
@require_auth(Permission.READ_ALERTS)
def get_alerts():
    limit = min(int(request.args.get("limit", 50)), 500)
    severity = request.args.get("severity")

    query = DBAlert.query.order_by(DBAlert.created_at.desc())
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
