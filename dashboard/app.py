import os
from datetime import datetime

import dash
import dash_auth
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from dash import Input, Output, dcc, html
from flask import Flask

# Initialize Flask
server = Flask(__name__)

# Initialize Dash with custom assets folder for fonts if needed,
# but we will use CDN for fonts in the layout.
app = dash.Dash(
    __name__,
    server=server,
    url_base_pathname="/dashboard/",
    external_stylesheets=[
        dbc.themes.DARKLY,  # Base dark theme
        "https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap",
        "https://use.fontawesome.com/releases/v6.0.0/css/all.css",
    ],
    suppress_callback_exceptions=True,
    title="Sentinel NetLab",
)

# Configuration
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

# --- Styling Constants ---
COLOR_PRIMARY = "#00f2fe"
COLOR_SECONDARY = "#4facfe"
COLOR_DANGER = "#ff0844"
COLOR_WARNING = "#f7b733"
COLOR_SUCCESS = "#00dbde"
COLOR_BG = "#050510"
GLASS_STYLE = {
    "background": "rgba(20, 20, 35, 0.4)",
    "backdropFilter": "blur(12px)",
    "WebkitBackdropFilter": "blur(12px)",
    "border": "1px solid rgba(255, 255, 255, 0.08)",
    "borderRadius": "16px",
    "boxShadow": "0 8px 32px 0 rgba(0, 0, 0, 0.3)",
}

# --- Layout Components ---

sidebar = html.Div(
    [
        html.Div(
            [
                html.Img(
                    src="/assets/logo.png",
                    style={"height": "40px", "marginTop": "-5px"},
                ),
                html.Span(
                    "SENTINEL NET",
                    className="ms-3",
                    style={
                        "fontSize": "1.2rem",
                        "fontWeight": "700",
                        "color": "#fff",
                        "letterSpacing": "1px",
                    },
                ),
            ],
            className="d-flex align-items-center mb-5 px-2",
        ),
        dbc.Nav(
            [
                dbc.NavLink(
                    [html.I(className="fas fa-chart-pie nav-icon"), "Dashboard"],
                    href="/dashboard/",
                    active="exact",
                ),
                dbc.NavLink(
                    [html.I(className="fas fa-wifi nav-icon"), "Networks"],
                    href="/dashboard/networks",
                    active="exact",
                ),
                dbc.NavLink(
                    [html.I(className="fas fa-shield-alt nav-icon"), "Security Alerts"],
                    href="/dashboard/alerts",
                    active="exact",
                ),
                dbc.NavLink(
                    [html.I(className="fas fa-cogs nav-icon"), "Audit Remediation"],
                    href="/dashboard/audit",
                    active="exact",
                    disabled=True,
                ),
            ],
            vertical=True,
            pills=True,
        ),
        html.Div(
            [
                html.Hr(style={"borderColor": "rgba(255,255,255,0.1)"}),
                html.Div(
                    [
                        html.Small(
                            "SYSTEM STATUS",
                            className="text-muted",
                            style={"fontSize": "0.7rem", "letterSpacing": "1px"},
                        ),
                        html.Div(
                            [
                                html.Div(
                                    className="rounded-circle bg-success",
                                    style={
                                        "width": "8px",
                                        "height": "8px",
                                        "marginRight": "8px",
                                    },
                                ),
                                html.Span(
                                    "Controller Online",
                                    style={"color": "#4caf50", "fontSize": "0.85rem"},
                                ),
                            ],
                            className="d-flex align-items-center mt-2",
                        ),
                        html.Div(
                            id="last-update",
                            style={
                                "color": "#666",
                                "fontSize": "0.75rem",
                                "marginTop": "5px",
                            },
                        ),
                    ],
                    className="px-2",
                ),
            ],
            style={"marginTop": "auto"},
        ),
    ],
    className="sidebar d-flex flex-column",
)


def build_stat_card(title, id_name, icon_class, color_class="text-white"):
    return html.Div(
        [
            html.Div(title, className="stat-label"),
            html.Div(
                [
                    html.H2(
                        "0", id=id_name, className=f"stat-value {color_class} mb-0"
                    ),
                    html.I(
                        className=f"{icon_class} fa-lg opacity-50",
                        style={"marginLeft": "auto", "color": "rgba(255,255,255,0.2)"},
                    ),
                ],
                className="d-flex align-items-end",
            ),
            # Animated graphical element (placeholder for sparkline)
            html.Div(
                style={
                    "height": "4px",
                    "width": "100%",
                    "background": f"linear-gradient(90deg, {COLOR_PRIMARY}, transparent)",
                    "borderRadius": "2px",
                    "marginTop": "15px",
                    "opacity": "0.6",
                }
            ),
        ],
        style=GLASS_STYLE,
        className="p-4 h-100 stat-card",
    )


content = html.Div(
    [
        # Header
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.H4("Overview", className="fw-bold text-white mb-0"),
                        html.Span(
                            "Real-time network surveillance",
                            className="text-muted small",
                        ),
                    ]
                )
            ),
            className="mb-4",
        ),
        # Stats Row
        dbc.Row(
            [
                dbc.Col(
                    build_stat_card(
                        "Active Sensors", "sensor-count", "fas fa-satellite-dish"
                    ),
                    md=4,
                    className="mb-4",
                ),
                dbc.Col(
                    build_stat_card(
                        "Threats Detected",
                        "alert-count",
                        "fas fa-biohazard",
                        "text-danger",
                    ),
                    md=4,
                    className="mb-4",
                ),
                dbc.Col(
                    build_stat_card(
                        "Networks Scanned",
                        "network-count",
                        "fas fa-network-wired",
                        "text-warning",
                    ),
                    md=4,
                    className="mb-4",
                ),
            ],
            className="mb-2",
        ),
        # Main Dashboard Grid
        dbc.Row(
            [
                # Map Section (Left, Larger)
                dbc.Col(
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H5(
                                        "Wardriving Heatmap",
                                        className="fw-bold text-white mb-0",
                                    ),
                                    dbc.Button(
                                        html.I(className="fas fa-expand"),
                                        color="link",
                                        size="sm",
                                        className="text-muted",
                                    ),
                                ],
                                className="d-flex justify-content-between align-items-center mb-3",
                            ),
                            dcc.Graph(
                                id="heatmap-graph",
                                style={
                                    "height": "500px",
                                    "borderRadius": "12px",
                                    "overflow": "hidden",
                                },
                                config={"displayModeBar": False, "scrollZoom": True},
                            ),
                        ],
                        style=GLASS_STYLE,
                        className="p-3",
                    ),
                    lg=8,
                    className="mb-4",
                ),
                # Alerts Feed (Right, Smaller)
                dbc.Col(
                    html.Div(
                        [
                            html.H5(
                                "Recent Alerts", className="fw-bold text-white mb-3"
                            ),
                            html.Div(
                                id="alerts-table",
                                style={"maxHeight": "500px", "overflowY": "auto"},
                            ),
                        ],
                        style=GLASS_STYLE,
                        className="p-3 h-100",
                    ),
                    lg=4,
                    className="mb-4",
                ),
            ]
        ),
        # Operational Analytics Row
        dbc.Row(
            [
                # Sensor Health Table
                dbc.Col(
                    html.Div(
                        [
                            html.H5(
                                "Sensor Fleet Status",
                                className="fw-bold text-white mb-3",
                            ),
                            html.Div(
                                id="sensor-table",
                                style={"maxHeight": "300px", "overflowY": "auto"},
                            ),
                        ],
                        style=GLASS_STYLE,
                        className="p-3 h-100",
                    ),
                    lg=6,
                    className="mb-4",
                ),
                # Security Distribution Chart
                dbc.Col(
                    html.Div(
                        [
                            html.H5(
                                "Security Posture", className="fw-bold text-white mb-3"
                            ),
                            dcc.Graph(
                                id="security-pie-chart",
                                style={"height": "300px"},
                                config={"displayModeBar": False},
                            ),
                        ],
                        style=GLASS_STYLE,
                        className="p-3 h-100",
                    ),
                    lg=6,
                    className="mb-4",
                ),
            ]
        ),
    ],
    className="content",
)

app.layout = html.Div(
    [
        dcc.Location(id="url"),
        sidebar,
        content,
        dcc.Interval(
            id="interval-component",
            interval=5000,  # Update every 5 seconds for a more "live" feel
            n_intervals=0,
        ),
    ]
)


@app.callback(
    [
        Output("heatmap-graph", "figure"),
        Output("sensor-count", "children"),
        Output("alert-count", "children"),
        Output("network-count", "children"),
        Output("alerts-table", "children"),
        Output("last-update", "children"),
        Output("sensor-table", "children"),
        Output("security-pie-chart", "figure"),
    ],
    [Input("interval-component", "n_intervals")],
)
def update_metrics(n):
    current_time = datetime.now().strftime("Last updated: %H:%M:%S")

    # Dark Map Style
    layout_override = {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "margin": {"l": 0, "r": 0, "t": 0, "b": 0},
        "font": {"color": "#fff"},
        "mapbox": {
            "style": "carto-darkmatter",
            "center": {"lat": 40.7128, "lon": -74.0060},  # Default center
            "zoom": 2,
        },
    }

    empty_figure = go.Figure()
    empty_figure.update_layout(**layout_override)

    try:
        # 1. Fetch Data
        networks = []
        alerts = []
        sensors = {}

        try:
            # Networks
            resp_net = requests.get(
                f"{CONTROLLER_API}/api/v1/networks", headers=HEADERS, timeout=2
            )
            if resp_net.status_code == 200:
                networks = resp_net.json().get("networks", [])

            # Alerts
            resp_alerts = requests.get(
                f"{CONTROLLER_API}/api/v1/alerts", headers=HEADERS, timeout=2
            )
            if resp_alerts.status_code == 200:
                alerts = resp_alerts.json().get("alerts", [])

            # Sensors
            resp_sensors = requests.get(
                f"{CONTROLLER_API}/api/v1/sensors", headers=HEADERS, timeout=2
            )
            if resp_sensors.status_code == 200:
                sensors = resp_sensors.json().get("sensors", {})

        except Exception as e:
            app.server.logger.debug(f"Dashboard data fetch failed (graceful): {e}")
            pass  # Graceful degrade

        # --- PROCESS NETWORKS & MAP ---
        map_fig = go.Figure(go.Scattermapbox())
        map_fig.update_layout(**layout_override)

        security_counts = {"OPEN": 0, "WEP": 0, "WPA2": 0, "WPA3": 0}

        if networks:
            data = []
            for n in networks:
                # Map Data
                if n.get("lat") and n.get("lon"):
                    data.append(
                        {
                            "lat": n.get("lat"),
                            "lon": n.get("lon"),
                            "ssid": n.get("ssid", "Unknown"),
                            "risk": n.get("risk_score", 0),
                            "bssid": n.get("bssid", ""),
                        }
                    )

                # Security Stats
                sec = n.get("security", "OPEN").upper()
                # Simple normalization
                if "WPA3" in sec:
                    security_counts["WPA3"] += 1
                elif "WPA2" in sec:
                    security_counts["WPA2"] += 1
                elif "WEP" in sec:
                    security_counts["WEP"] += 1
                else:
                    security_counts["OPEN"] += 1

            if data:
                df = pd.DataFrame(data)
                map_fig = px.density_mapbox(
                    df,
                    lat="lat",
                    lon="lon",
                    z="risk",
                    radius=20,
                    center={"lat": df.lat.mean(), "lon": df.lon.mean()},
                    zoom=12,
                    mapbox_style="carto-darkmatter",
                    color_continuous_scale=["#00f2fe", "#4facfe", "#ffea00", "#ff0844"],
                    hover_data=["ssid", "bssid", "risk"],
                )
                map_fig.update_layout(**layout_override)
                map_fig.update_coloraxes(showscale=False)

        # --- PROCESS ALERTS TABLE ---
        alert_rows = []
        if alerts:
            for a in alerts[:8]:
                severity = a.get("severity", "Info")
                color = {
                    "Critical": "#ff0844",
                    "High": "#ffb199",
                    "Medium": "#f7b733",
                    "Low": "#00dbde",
                }.get(severity, "#8898aa")
                alert_rows.append(
                    html.Tr(
                        [
                            html.Td(
                                html.Div(
                                    style={
                                        "width": "6px",
                                        "height": "6px",
                                        "borderRadius": "50%",
                                        "background": color,
                                    }
                                ),
                                style={"width": "20px"},
                            ),
                            html.Td(
                                [
                                    html.Div(
                                        a.get("title", "Alert"),
                                        className="fw-bold text-white",
                                        style={"fontSize": "0.9rem"},
                                    ),
                                    html.Div(
                                        a.get("message", "")[:40] + "...",
                                        className="text-muted small",
                                    ),
                                ]
                            ),
                            html.Td(
                                html.Small(
                                    a.get("timestamp", "")[11:16],
                                    className="text-muted",
                                ),
                                className="text-end",
                            ),
                        ]
                    )
                )
            alerts_component = dbc.Table(
                html.Tbody(alert_rows),
                borderless=True,
                className="table-custom mb-0",
                hover=True,
            )
        else:
            alerts_component = html.Div(
                [
                    html.I(
                        className="fas fa-check-circle fa-2x mb-3 text-success",
                        style={"opacity": "0.5"},
                    ),
                    html.H6("All Systems Normal", className="text-white"),
                ],
                className="text-center p-5",
            )

        # --- PROCESS SENSOR TABLE ---
        sensor_rows = []
        if sensors:
            for sid, sdata in sensors.items():
                status = sdata.get("status", "offline")
                status_color = "#00dbde" if status == "online" else "#8898aa"
                sensor_rows.append(
                    html.Tr(
                        [
                            html.Td(html.I(className="fas fa-microchip text-muted")),
                            html.Td(sid, className="fw-bold text-white"),
                            html.Td(
                                html.Span(
                                    status.upper(),
                                    style={
                                        "color": status_color,
                                        "fontSize": "0.8rem",
                                        "fontWeight": "bold",
                                    },
                                )
                            ),
                            html.Td(
                                sdata.get("last_seen", "")[11:19],
                                className="text-muted small text-end",
                            ),
                        ]
                    )
                )
            sensor_table = dbc.Table(
                html.Tbody(sensor_rows),
                borderless=True,
                className="table-custom mb-0",
                hover=True,
            )
        else:
            sensor_table = html.Div(
                "No active sensors", className="text-center text-muted p-3"
            )

        # --- PROCESS SECURITY PIE CHART ---
        pie_fig = px.pie(
            names=list(security_counts.keys()),
            values=list(security_counts.values()),
            hole=0.6,
            color_discrete_sequence=[
                "#ff0844",
                "#f7b733",
                "#00dbde",
                "#00f2fe",
            ],  # WPA3/2/WEP/Openish colors
        )
        pie_fig.update_layout(
            **layout_override,
            showlegend=True,
            legend={
                "orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1
            },
        )
        # Update text info
        pie_fig.update_traces(textinfo="percent+label", textposition="inside")

        # Counters
        s_count = str(len(sensors))
        a_count = str(len(alerts))
        n_count = str(len(networks))

        return (
            map_fig,
            s_count,
            a_count,
            n_count,
            alerts_component,
            current_time,
            sensor_table,
            pie_fig,
        )

    except Exception as e:
        print(f"Error update: {e}")
        return (
            empty_figure,
            "-",
            "-",
            "-",
            html.Div("Error"),
            current_time,
            html.Div("Error"),
            empty_figure,
        )


if __name__ == "__main__":
    import os
    host = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.getenv("DASHBOARD_PORT", "8050"))
    # Bandit B104: Hardcoded bind all interfaces
    # We allow 0.0.0.0 via env var for containerized deployments.
    app.run_server(debug=True, host=host, port=port)
