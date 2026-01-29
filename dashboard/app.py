import os

import dash
import dash_auth
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from dash import Input, Output, dcc, html
from flask import Flask

# Initialize Flask (wrapped by controller or standalone)
server = Flask(__name__)

# Initialize Dash with custom theme
app = dash.Dash(
    __name__,
    server=server,
    url_base_pathname="/dashboard/",
    external_stylesheets=[dbc.themes.CYBORG],  # Modern dark theme
    suppress_callback_exceptions=True,
)

# Configuration from env or defaults
CONTROLLER_API = os.environ.get("CONTROLLER_URL", "http://localhost:5000")
API_TOKEN = os.environ.get("DASHBOARD_API_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}

# Security
VALID_USERNAME_PASSWORD_PAIRS = {
    os.environ.get("DASH_USERNAME", "admin"): os.environ.get(
        "DASH_PASSWORD", "sentinel"
    )
}
auth = dash_auth.BasicAuth(app, VALID_USERNAME_PASSWORD_PAIRS)

# Custom CSS
CUSTOM_CSS = """
.gradient-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid #0f3460;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.gradient-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
}
.stat-number {
    font-size: 3rem;
    font-weight: 700;
    background: linear-gradient(90deg, #00d9ff, #00ff88);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.stat-number-danger {
    background: linear-gradient(90deg, #ff4757, #ff6b81);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.stat-number-warning {
    background: linear-gradient(90deg, #ffa502, #ffcd38);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.section-header {
    font-weight: 600;
    color: #a0a0a0;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
}
.main-title {
    background: linear-gradient(90deg, #00d9ff, #00ff88);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 700;
}
.footer {
    text-align: center;
    color: #666;
    padding: 2rem 0;
    font-size: 0.85rem;
}
"""

# Layout
app.layout = html.Div(
    [
        # Inject custom CSS
        html.Style(CUSTOM_CSS),
        
        # Navbar
        dbc.Navbar(
            dbc.Container(
                [
                    dbc.Row(
                        [
                            dbc.Col(
                                html.Img(src="/assets/logo.png", height="40px"),
                                width="auto",
                                className="d-none d-md-block",
                            ),
                            dbc.Col(
                                dbc.NavbarBrand(
                                    "Sentinel NetLab",
                                    className="ms-2 main-title",
                                    style={"fontSize": "1.5rem"},
                                ),
                            ),
                        ],
                        align="center",
                        className="g-0",
                    ),
                    dbc.NavbarToggler(id="navbar-toggler"),
                    dbc.Collapse(
                        dbc.Nav(
                            [
                                dbc.NavItem(
                                    dbc.NavLink("Dashboard", href="#", active=True)
                                ),
                                dbc.NavItem(dbc.NavLink("Networks", href="#networks")),
                                dbc.NavItem(dbc.NavLink("Alerts", href="#alerts")),
                            ],
                            className="ms-auto",
                            navbar=True,
                        ),
                        id="navbar-collapse",
                        navbar=True,
                    ),
                ],
                fluid=True,
            ),
            color="dark",
            dark=True,
            sticky="top",
            className="mb-4",
            style={"borderBottom": "1px solid #0f3460"},
        ),
        
        # Main Content
        dbc.Container(
            [
                # Stats Row
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.P("ACTIVE SENSORS", className="section-header"),
                                        html.H1(
                                            "0",
                                            id="sensor-count",
                                            className="stat-number",
                                        ),
                                        html.P(
                                            "Monitoring WiFi Networks",
                                            className="text-muted small",
                                        ),
                                    ]
                                ),
                                className="gradient-card h-100",
                            ),
                            md=4,
                            className="mb-4",
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.P("SECURITY ALERTS", className="section-header"),
                                        html.H1(
                                            "0",
                                            id="alert-count",
                                            className="stat-number stat-number-danger",
                                        ),
                                        html.P(
                                            "Threats Detected",
                                            className="text-muted small",
                                        ),
                                    ]
                                ),
                                className="gradient-card h-100",
                            ),
                            md=4,
                            className="mb-4",
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.P("NETWORKS SCANNED", className="section-header"),
                                        html.H1(
                                            "0",
                                            id="network-count",
                                            className="stat-number stat-number-warning",
                                        ),
                                        html.P(
                                            "Unique BSSIDs",
                                            className="text-muted small",
                                        ),
                                    ]
                                ),
                                className="gradient-card h-100",
                            ),
                            md=4,
                            className="mb-4",
                        ),
                    ],
                    className="mb-4",
                ),
                
                # Map Section
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                [
                                    dbc.CardHeader(
                                        [
                                            html.I(className="fas fa-map-marked-alt me-2"),
                                            "Wardriving Heatmap",
                                        ],
                                        style={"background": "#1a1a2e", "border": "none"},
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(
                                                id="heatmap-graph",
                                                style={"height": "500px"},
                                                config={"displayModeBar": False},
                                            ),
                                            type="circle",
                                            color="#00d9ff",
                                        ),
                                        style={"padding": "0"},
                                    ),
                                ],
                                className="gradient-card",
                            ),
                            width=12,
                            className="mb-4",
                        )
                    ]
                ),
                
                # Alerts Section
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                [
                                    dbc.CardHeader(
                                        [
                                            html.I(className="fas fa-exclamation-triangle me-2"),
                                            "Recent Security Alerts",
                                        ],
                                        style={"background": "#1a1a2e", "border": "none"},
                                    ),
                                    dbc.CardBody(
                                        html.Div(id="alerts-table"),
                                    ),
                                ],
                                className="gradient-card",
                            ),
                            width=12,
                        )
                    ]
                ),
                
                # Footer
                html.Div(
                    [
                        html.Hr(style={"borderColor": "#333"}),
                        html.P(
                            [
                                "Sentinel NetLab v1.0.0 • ",
                                html.A(
                                    "Documentation",
                                    href="https://github.com/Anduong1200/sentinel-netlab",
                                    target="_blank",
                                    style={"color": "#00d9ff"},
                                ),
                                " • Last Update: ",
                                html.Span(id="last-update", children="--"),
                            ],
                            className="footer",
                        ),
                    ],
                    className="mt-5",
                ),
                
                dcc.Interval(
                    id="interval-component",
                    interval=10 * 1000,  # 10 seconds
                    n_intervals=0,
                ),
            ],
            fluid=True,
            style={"maxWidth": "1600px"},
        ),
    ],
    style={"backgroundColor": "#0d1117", "minHeight": "100vh"},
)


@app.callback(
    [
        Output("heatmap-graph", "figure"),
        Output("sensor-count", "children"),
        Output("alert-count", "children"),
        Output("network-count", "children"),
        Output("alerts-table", "children"),
        Output("last-update", "children"),
    ],
    [Input("interval-component", "n_intervals")],
)
def update_metrics(n):
    from datetime import datetime
    
    # Default empty map with dark styling
    empty_map = go.Figure(
        go.Scattermapbox()
    )
    empty_map.update_layout(
        mapbox=dict(
            style="carto-darkmatter",
            center={"lat": 0, "lon": 0},
            zoom=1,
        ),
        margin={"r": 0, "t": 0, "l": 0, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    
    current_time = datetime.now().strftime("%H:%M:%S")

    try:
        # 1. Get Wardriving/Network Data
        resp_net = requests.get(
            f"{CONTROLLER_API}/api/v1/networks", headers=HEADERS, timeout=5
        )
        networks = (
            resp_net.json().get("networks", []) if resp_net.status_code == 200 else []
        )

        # 2. Get Alerts
        resp_alerts = requests.get(
            f"{CONTROLLER_API}/api/v1/alerts", headers=HEADERS, timeout=5
        )
        alerts = (
            resp_alerts.json().get("alerts", [])
            if resp_alerts.status_code == 200
            else []
        )

        # Process Map
        if networks:
            data = [
                {
                    "lat": n.get("lat", 0),
                    "lon": n.get("lon", 0),
                    "ssid": n.get("ssid", "Unknown"),
                    "risk": n.get("risk_score", 0),
                    "bssid": n.get("bssid", ""),
                }
                for n in networks
                if n.get("lat")
            ]

            if data:
                df = pd.DataFrame(data)
                fig = px.density_mapbox(
                    df,
                    lat="lat",
                    lon="lon",
                    z="risk",
                    radius=25,
                    center={"lat": df.lat.mean(), "lon": df.lon.mean()},
                    zoom=13,
                    mapbox_style="carto-darkmatter",
                    color_continuous_scale="Turbo",
                    hover_data=["ssid", "bssid", "risk"],
                )
                fig.update_layout(
                    margin={"r": 0, "t": 0, "l": 0, "b": 0},
                    paper_bgcolor="rgba(0,0,0,0)",
                    coloraxis_colorbar=dict(
                        title="Risk",
                        tickfont=dict(color="#888"),
                        titlefont=dict(color="#888"),
                    ),
                )
            else:
                fig = empty_map
        else:
            fig = empty_map

        # Process Alerts Table
        if alerts:
            table_header = [
                html.Thead(
                    html.Tr(
                        [
                            html.Th("Time", style={"width": "15%"}),
                            html.Th("Severity", style={"width": "10%"}),
                            html.Th("Type", style={"width": "15%"}),
                            html.Th("Message", style={"width": "40%"}),
                            html.Th("Action", style={"width": "20%"}),
                        ]
                    ),
                    style={"background": "#1a1a2e"},
                )
            ]
            rows = []
            for a in alerts[:10]:
                severity = a.get("severity", "Info")
                badge_color = {
                    "Critical": "danger",
                    "High": "warning", 
                    "Medium": "info",
                    "Low": "secondary",
                }.get(severity, "light")
                
                rows.append(
                    html.Tr(
                        [
                            html.Td(a.get("timestamp", "")[:19]),
                            html.Td(dbc.Badge(severity, color=badge_color)),
                            html.Td(a.get("alert_type", "")),
                            html.Td(a.get("title", a.get("message", ""))),
                            html.Td(
                                dbc.Button(
                                    "Investigate",
                                    color="outline-info",
                                    size="sm",
                                )
                            ),
                        ],
                    )
                )

            table_body = [html.Tbody(rows)]
            table = dbc.Table(
                table_header + table_body,
                bordered=False,
                dark=True,
                hover=True,
                responsive=True,
                striped=True,
                style={"marginBottom": 0},
            )
        else:
            table = dbc.Alert(
                [
                    html.I(className="fas fa-check-circle me-2"),
                    "All clear! No security alerts detected.",
                ],
                color="success",
                className="mb-0",
            )

        return (
            fig,
            str(len({n.get("sensor_id") for n in networks})),
            str(len(alerts)),
            str(len(networks)),
            table,
            current_time,
        )

    except Exception as e:
        print(f"Dashboard Update Error: {e}")
        return (
            empty_map,
            "–",
            "–",
            "–",
            dbc.Alert(
                [
                    html.I(className="fas fa-exclamation-circle me-2"),
                    f"Connection Error: {e}",
                ],
                color="danger",
            ),
            current_time,
        )


if __name__ == "__main__":
    app.run_server(debug=True, host="0.0.0.0", port=8050)
