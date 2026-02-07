import os
import random
from datetime import datetime, timedelta

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from dash import Input, Output, callback, dcc, html

from dashboard.components.cards import COLOR_PRIMARY, GLASS_STYLE

dash.register_page(__name__, path="/signals", title="Sentinel NetLab - Signals")

# Configuration
CONTROLLER_API = os.environ.get("CONTROLLER_URL", "http://localhost:5000")
API_TOKEN = os.environ.get("DASHBOARD_API_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}

layout = html.Div(
    [
        # Header
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.H4("Signal Analysis", className="fw-bold text-white mb-0"),
                        html.Span(
                            "RF Environment Metrics & Telemetry",
                            className="text-muted small",
                        ),
                    ]
                )
            ),
            className="mb-4",
        ),
        # Charts Row 1
        dbc.Row(
            [
                dbc.Col(
                    html.Div(
                        [
                            html.H5("Channel Utilization", className="text-white mb-3"),
                            dcc.Graph(id="channel-graph", style={"height": "300px"}),
                        ],
                        style=GLASS_STYLE,
                        className="p-3 mb-4",
                    ),
                    md=6,
                ),
                dbc.Col(
                    html.Div(
                        [
                            html.H5(
                                "Signal Strength Distribution",
                                className="text-white mb-3",
                            ),
                            dcc.Graph(id="rssi-graph", style={"height": "300px"}),
                        ],
                        style=GLASS_STYLE,
                        className="p-3 mb-4",
                    ),
                    md=6,
                ),
            ]
        ),
        # Charts Row 2 (Time Series)
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.H5(
                            "Network Discovery Rate (24h)", className="text-white mb-3"
                        ),
                        dcc.Graph(id="discovery-graph", style={"height": "350px"}),
                    ],
                    style=GLASS_STYLE,
                    className="p-3",
                ),
                width=12,
            )
        ),
        dcc.Interval(
            id="signals-interval",
            interval=15000,  # Update every 15s
            n_intervals=0,
        ),
    ],
    className="content",
)


@callback(
    [
        Output("channel-graph", "figure"),
        Output("rssi-graph", "figure"),
        Output("discovery-graph", "figure"),
    ],
    [Input("signals-interval", "n_intervals")],
)
def update_signals(n):
    # Dark Style
    layout_override = {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "margin": {"l": 40, "r": 20, "t": 20, "b": 40},
        "font": {"color": "#fff"},
        "xaxis": {"gridcolor": "rgba(255,255,255,0.1)"},
        "yaxis": {"gridcolor": "rgba(255,255,255,0.1)"},
    }

    try:
        # Fetch Data (Real snapshot)
        networks = []
        try:
            resp_net = requests.get(
                f"{CONTROLLER_API}/api/v1/networks", headers=HEADERS, timeout=3
            )
            if resp_net.status_code == 200:
                networks = resp_net.json().get("networks", [])
        except Exception:  # noqa: S110
            pass

        # === 1. Channel Graph ===
        if networks:
            channels = [n.get("channel") for n in networks if n.get("channel")]
            df_ch = pd.DataFrame(channels, columns=["channel"])
            fig_ch = px.histogram(
                df_ch, x="channel", nbins=14, color_discrete_sequence=[COLOR_PRIMARY]
            )
            fig_ch.update_layout(**layout_override)
            fig_ch.update_layout(bargap=0.2)
        else:
            fig_ch = go.Figure()
            fig_ch.update_layout(**layout_override)

        # === 2. RSSI Graph ===
        if networks:
            rssi = [n.get("rssi", -100) for n in networks if n.get("rssi")]
            # Filter out errors
            rssi = [r for r in rssi if -100 <= r <= 0]

            fig_rssi = go.Figure()
            fig_rssi.add_trace(
                go.Violin(
                    y=rssi,
                    box_visible=True,
                    line_color=COLOR_PRIMARY,
                    meanline_visible=True,
                    fillcolor="rgba(0, 242, 254, 0.2)",
                    name="RSSI (dBm)",
                )
            )
            fig_rssi.update_layout(**layout_override)
        else:
            fig_rssi = go.Figure()
            fig_rssi.update_layout(**layout_override)

        # === 3. Discovery Graph (Mocked Timeline) ===
        # Since we don't have historical API yet, we simulate a "trend" based on current count
        # In a real app, this would query `telemetry_1h`

        now = datetime.now()
        times = [(now - timedelta(hours=i)).strftime("%H:00") for i in range(24, 0, -1)]

        # Mock trend: randomly fluctuate around current count / 10
        base_count = max(len(networks) // 5, 5)
        counts = [max(0, base_count + random.randint(-2, 5)) for _ in times]  # noqa: S311

        fig_disc = go.Figure()
        fig_disc.add_trace(
            go.Scatter(
                x=times,
                y=counts,
                mode="lines+markers",
                fill="tozeroy",
                line={"color": "#f7b733", "width": 3},  # Orange/Gold
                name="New Networks",
            )
        )

        fig_disc.update_layout(**layout_override)
        fig_disc.update_layout(
            xaxis_title="Time (Last 24h)", yaxis_title="Networks Detected"
        )

        return fig_ch, fig_rssi, fig_disc

    except Exception as e:
        print(f"Signal Error: {e}")
        empty = go.Figure()
        empty.update_layout(**layout_override)
        return empty, empty, empty
