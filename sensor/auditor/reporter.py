import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate reports in various formats"""

    def __init__(self, templates_dir: Path | None = None):
        if templates_dir is None:
            # Point to the original templates dir
            templates_dir = Path(__file__).parent.parent / "templates"
        self.templates_dir = templates_dir

    def render_html(self, data: dict[str, Any]) -> str:
        """Render HTML report using Jinja2"""
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            logger.error("Jinja2 not installed. Run: pip install jinja2")
            return "<html><body><h1>Error: Jinja2 not installed</h1></body></html>"

        env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)), autoescape=True
        )
        template = env.get_template("report_template.html")
        return str(template.render(**data))

    def render_json(self, data: dict[str, Any]) -> str:
        """Render JSON report"""
        return json.dumps(data, indent=2, ensure_ascii=False)

    def save_report(
        self, data: dict[str, Any], output_path: Path, format: str = "json"
    ):
        """Save report to file"""
        if format == "html":
            content = self.render_html(data)
        else:
            content = self.render_json(data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Report saved to {output_path}")
