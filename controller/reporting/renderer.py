import html
from typing import Any


class SafeRenderer:
    """
    Centralized renderer for HTML content to prevent XSS.
    All inputs are automatically escaped.
    """

    @staticmethod
    def escape(text: Any) -> str:
        """Safe escape wrapper that handles None/Non-string types."""
        if text is None:
            return ""
        return html.escape(str(text))

    @classmethod
    def render_row(cls, data: dict[str, Any], columns: list[str]) -> str:
        """Render a table row with escaped cell values."""
        cells = []
        for col in columns:
            val = data.get(col, "")
            # Special handling for badges/formatting could go here,
            # but for now we assume raw data needs escaping.
            # If the value is a dict/complex object, we might need specific logic.
            # For this project's simple usage:
            cells.append(f"<td>{cls.escape(val)}</td>")

        return "<tr>" + "".join(cells) + "</tr>"

    @classmethod
    def render_finding(cls, finding: dict[str, str]) -> str:
        """Render a finding block with escaped content."""
        title = cls.escape(finding.get("title", "Finding"))
        desc = cls.escape(finding.get("description", ""))
        severity = cls.escape(finding.get("severity", "medium")).lower()

        # Safe HTML structure with escaped content injected
        return f"""
            <div class="finding {severity}">
                <h4>{title}</h4>
                <p>{desc}</p>
            </div>
        """

    @classmethod
    def render_list_item(cls, item: str) -> str:
        """Render a list item safely."""
        return f"<li>{cls.escape(item)}</li>"
