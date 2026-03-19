import os
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
                            "Network Discovery Rate (Volume Chart)",
                            className="text-white mb-3",
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
            interval=5000,  # Update every 5s
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
            rssi = [
                n.get("rssi_avg", -100)
                for n in networks
                if n.get("rssi_avg") is not None
            ]
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

        # === 3. Discovery Graph (Financial-Style Timeline) ===
        # Use actual 'first_seen' timestamps to calculate discovery rate per minute
        now = datetime.now()
        # Generate last 60 minutes bins (1 hour) to allow zooming
        times = [
            (now - timedelta(minutes=i)).strftime("%H:%M") for i in range(60, -1, -1)
        ]

        counts_dict = dict.fromkeys(times, 0)

        if networks:
            for net in networks:
                first_seen_ts = net.get("first_seen")
                if first_seen_ts:
                    net_time = datetime.fromtimestamp(first_seen_ts)
                    time_str = net_time.strftime("%H:%M")
                    if time_str in counts_dict:
                        counts_dict[time_str] += 1

        # Use full datetime objects for x-axis to support Plotly's native time rangeslider properly
        time_objs = [now - timedelta(minutes=i) for i in range(60, -1, -1)]
        counts = [counts_dict[t.strftime("%H:%M")] for t in time_objs]

        fig_disc = go.Figure()

        # Add Volume-like Bar Chart (Typical for "Rate" in financial charts)
        fig_disc.add_trace(
            go.Bar(
                x=time_objs,
                y=counts,
                marker_color="#00f2fe",  # Cyan
                name="New Networks",
            )
        )

        # Add Trendline overlay (Scatter)
        fig_disc.add_trace(
            go.Scatter(
                x=time_objs,
                y=counts,
                mode="lines",
                line={
                    "color": "#f7b733",
                    "width": 2,
                    "shape": "spline",
                },  # Smooth orange line
                name="Trend",
            )
        )

        fig_disc.update_layout(**layout_override)
        fig_disc.update_layout(
            yaxis_title="Networks Detected/Min",
            xaxis={
                "rangeselector": {
                    "buttons": [
                        {
                            "count": 5,
                            "label": "5m",
                            "step": "minute",
                            "stepmode": "backward",
                        },
                        {
                            "count": 15,
                            "label": "15m",
                            "step": "minute",
                            "stepmode": "backward",
                        },
                        {
                            "count": 30,
                            "label": "30m",
                            "step": "minute",
                            "stepmode": "backward",
                        },
                        {"step": "all", "label": "1H"},
                    ],
                    "bgcolor": "rgba(0,0,0,0.6)",
                    "activecolor": "rgba(0,242,254,0.4)",
                    "font": {"color": "#ffffff"},
                },
                "rangeslider": {
                    "visible": True,
                    "thickness": 0.1,
                    "bgcolor": "rgba(255,255,255,0.05)",
                },
                "type": "date",
            },
            hovermode="x unified",
            showlegend=False,
        )

        return fig_ch, fig_rssi, fig_disc

    except Exception as e:
        print(f"Signal Error: {e}")
        empty = go.Figure()
        empty.update_layout(**layout_override)
        return empty, empty, empty
