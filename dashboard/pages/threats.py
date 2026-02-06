
import os

import dash
import dash_bootstrap_components as dbc
import requests
from dash import Input, Output, callback, dcc, html

from dashboard.components.cards import GLASS_STYLE

dash.register_page(__name__, path="/threats", title="Sentinel NetLab - Threats")

# Configuration
CONTROLLER_API = os.environ.get("CONTROLLER_URL", "http://localhost:5000")
API_TOKEN = os.environ.get("DASHBOARD_API_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}

layout = html.Div(
    [
        # Header & Controls
        dbc.Row(
            [
                dbc.Col(
                    html.Div(
                        [
                            html.H4("Threat Matrix", className="fw-bold text-white mb-0"),
                            html.Span(
                                "Live feed of detected security incidents",
                                className="text-muted small",
                            ),
                        ]
                    ),
                    md=8,
                ),
                dbc.Col(
                    dcc.Dropdown(
                        id="threat-severity-filter",
                        options=[
                            {"label": "All Severities", "value": "ALL"},
                            {"label": "Critical", "value": "Critical"},
                            {"label": "High", "value": "High"},
                            {"label": "Medium", "value": "Medium"},
                            {"label": "Low", "value": "Low"},
                        ],
                        value="ALL",
                        clearable=False,
                        style={"color": "#333"},
                    ),
                    md=4,
                ),
            ],
            className="mb-4 align-items-center",
        ),

        # Threat Table
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.Div(id="threats-grid"),
                    ],
                    style=GLASS_STYLE,
                    className="p-3",
                ),
                width=12,
            )
        ),
         dcc.Interval(
            id="threats-interval",
            interval=10000, # Update every 10s
            n_intervals=0,
        ),
    ],
    className="content",
)


@callback(
    Output("threats-grid", "children"),
    [
        Input("threats-interval", "n_intervals"),
        Input("threat-severity-filter", "value")
    ],
)
def update_threats(n, filter_val):
    try:
        # Fetch Data
        alerts = []
        try:
            resp_alerts = requests.get(
                f"{CONTROLLER_API}/api/v1/alerts", headers=HEADERS, timeout=3
            )
            if resp_alerts.status_code == 200:
                alerts = resp_alerts.json().get("alerts", [])
        except Exception: # noqa: S110
             pass

        filtered_alerts = []
        for a in alerts:
            sev = a.get("severity", "Info")
            if filter_val != "ALL" and sev != filter_val:
                continue

            # Enrich/Format
            a['time_str'] = a.get("timestamp", "")[11:19]
            filtered_alerts.append(a)

        if not filtered_alerts:
             return html.Div(
                "No active threats match current filter.",
                className="text-center text-muted p-5"
             )

        # Build Table
        # Using simple HTML table loop for maximum customizability over formatting
        rows = []
        for a in filtered_alerts:
            severity = a.get("severity", "Info")
            color = {
                "Critical": "#ff0844",
                "High": "#ffb199",
                "Medium": "#f7b733",
                "Low": "#00dbde",
            }.get(severity, "#8898aa")

            rows.append(
                html.Tr(
                    [
                        html.Td(
                             html.Div(
                                severity.upper(),
                                className="badge",
                                style={"backgroundColor": color, "color": "#111", "minWidth": "80px"}
                             )
                        ),
                        html.Td(a.get("title", "Unknown"), className="fw-bold text-white"),
                        html.Td(a.get("message", "-"), className="text-muted"),
                        html.Td(html.Code(a.get("bssid", "N/A"), className="text-primary")),
                        html.Td(a.get("time_str"), className="text-end text-white font-monospace"),
                    ]
                )
            )

        table = dbc.Table(
            [
                html.Thead(
                    html.Tr(
                        [
                            html.Th("SEVERITY", style={"width": "100px"}),
                            html.Th("ALERT TYPE"),
                            html.Th("DETAILS"),
                            html.Th("SOURCE BSSID"),
                            html.Th("TIME", className="text-end"),
                        ]
                    )
                ),
                html.Tbody(rows),
            ],
            hover=True,
            borderless=True,
            className="table-custom"
        )

        return table

    except Exception as e:
        return html.Div(f"Error loading threats: {e}", className="text-danger")
