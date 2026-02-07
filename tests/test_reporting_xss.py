from pathlib import Path
from tempfile import TemporaryDirectory

from controller.export_engine import ReportData, ReportEngine, ReportFormat, ReportType
from controller.reporting.renderer import SafeRenderer


def test_safe_renderer_escaping():
    """Verify SafeRenderer escapes HTML entities."""
    # 1. Basic escaping
    payload = "<script>alert(1)</script>"
    escaped = SafeRenderer.escape(payload)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" == escaped

    # 2. None handling
    assert SafeRenderer.escape(None) == ""

    # 3. Finding rendering
    finding = {
        "title": "Bad <script> Title",
        "description": "Desc with <b>bold</b> injection",
        "severity": "high",
    }
    rendered = SafeRenderer.render_finding(finding)
    assert "Bad &lt;script&gt; Title" in rendered
    assert "&lt;b&gt;bold&lt;/b&gt;" in rendered
    assert '<div class="finding high">' in rendered

    # 4. List rendering
    item = "List <item>"
    assert "<li>List &lt;item&gt;</li>" == SafeRenderer.render_list_item(item)


def test_report_engine_xss_integration():
    """Verify ReportEngine generates XSS-safe HTML."""
    with TemporaryDirectory() as tmpdir:
        engine = ReportEngine(Path(tmpdir))

        # Create data with XSS payloads
        data = ReportData(
            report_type=ReportType.SECURITY_ASSESSMENT,
            title="<script>Title</script>",
            generated_at="2026-01-01",
            networks=[
                {
                    "bssid": "00:11:22:33:44:55",
                    "ssid": "<img src=x onerror=alert(1)>",
                    "channel": 1,
                    "security": "Open",
                    "risk_level": "critical",
                }
            ],
            findings=[
                {
                    "title": "XSS <Finding>",
                    "description": "Bad <br> tag",
                    "severity": "medium",
                }
            ],
            recommendations=["Rec <1>"],
        )

        # Generate HTML
        output_path = engine.generate(data, ReportFormat.HTML)
        content = output_path.read_text(encoding="utf-8")

        # Verify content is escaped
        # Title in <title> and <h1>
        assert "&lt;script&gt;Title&lt;/script&gt;" in content
        assert "<script>Title</script>" not in content

        # SSID in table
        assert "&lt;img src=x onerror=alert(1)&gt;" in content
        assert "<img src=x onerror=alert(1)>" not in content

        # Finding
        assert "XSS &lt;Finding&gt;" in content
        assert "Bad &lt;br&gt; tag" in content

        # Recommendation
        assert "Rec &lt;1&gt;" in content
