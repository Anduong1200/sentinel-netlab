
import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, dcc, html, callback
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import requests
import os

from dashboard.components.cards import GLASS_STYLE

dash.register_page(__name__, path="/map", title="Sentinel NetLab - Global Map")

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
                            html.H4("Global Intelligence Map", className="fw-bold text-white mb-0"),
                            html.Span(
                                "Geospatial visualization of discovered networks",
                                className="text-muted small",
                            ),
                        ]
                    ),
                    md=8,
                ),
                dbc.Col(
                    dcc.Dropdown(
                        id="map-security-filter",
                        options=[
                            {"label": "All Protocols", "value": "ALL"},
                            {"label": "Open / Insecure", "value": "OPEN"},
                            {"label": "WEP (Legacy)", "value": "WEP"},
                            {"label": "WPA2/WPA3", "value": "WPA"},
                        ],
                        value="ALL",
                        clearable=False,
                        style={"color": "#333"},  # Override dark mode for dropdown text
                    ),
                    md=4,
                ),
            ],
            className="mb-4 align-items-center",
        ),
        # Map Container
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        dcc.Graph(
                            id="advanced-map-graph",
                            style={
                                "height": "75vh",
                                "borderRadius": "12px",
                                "overflow": "hidden",
                            },
                            config={"displayModeBar": True, "scrollZoom": True},
                        ),
                    ],
                    style=GLASS_STYLE,
                    className="p-3",
                ),
                width=12,
            )
        ),
         dcc.Interval(
            id="map-interval",
            interval=10000, # Update every 10s
            n_intervals=0,
        ),
    ],
    className="content",
)


@callback(
    Output("advanced-map-graph", "figure"),
    [
        Input("map-interval", "n_intervals"),
        Input("map-security-filter", "value")
    ],
)
def update_map(n, filter_val):
    # Dark Map Style
    layout_override = {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "margin": {"l": 0, "r": 0, "t": 0, "b": 0},
        "font": {"color": "#fff"},
        "mapbox": {
            "style": "carto-darkmatter",
            "center": {"lat": 40.7128, "lon": -74.0060}, 
            "zoom": 10,
        },
    }

    try:
        # Fetch Data
        networks = []
        try:
            resp_net = requests.get(
                f"{CONTROLLER_API}/api/v1/networks", headers=HEADERS, timeout=3
            )
            if resp_net.status_code == 200:
                networks = resp_net.json().get("networks", [])
        except:
            pass
            
        if not networks:
             fig = go.Figure(go.Scattermapbox())
             fig.update_layout(**layout_override)
             return fig

        # Filter Data
        filtered_nets = []
        for net in networks:
            if not (net.get("lat") and net.get("lon")):
                continue
            
            sec = net.get("security", "").upper()
            
            if filter_val == "OPEN" and "OPEN" not in sec:
                continue
            if filter_val == "WEP" and "WEP" not in sec:
                continue
            if filter_val == "WPA" and "WPA" not in sec:
                continue
                
            # Compute Color
            color = "#00dbde" # Cyan (Safe)
            if "WEP" in sec: color = "#f7b733" # Orange
            if "OPEN" in sec: color = "#ff0844" # Red
            
            net["color"] = color
            net["risk"] = net.get("risk_score", 0)
            filtered_nets.append(net)
            
        if not filtered_nets:
             fig = go.Figure(go.Scattermapbox())
             fig.update_layout(**layout_override)
             return fig

        df = pd.DataFrame(filtered_nets)

        # Plot
        fig = px.scatter_mapbox(
            df,
            lat="lat",
            lon="lon",
            hover_name="ssid",
            hover_data=["bssid", "security", "channel", "risk"],
            color_discrete_sequence=[df.iloc[0]["color"]] if len(df) == 1 else df["color"], # Simple hack, better to map
            zoom=12,
            height=600
        )
        
        # Manually set colors scatter for multiple traces? 
        # px.scatter_mapbox with 'color' column requires careful mapping.
        # Let's use graph_objects for precise control if needed, but PX is easier.
        # PX with 'color_discrete_sequence' is tricky if we don't use 'color' dim.
        
        # Better: Use 'risk' for color or 'security' category.
        fig = px.scatter_mapbox(
            df,
            lat="lat",
            lon="lon",
            color="risk", # Color by Risk Score
            size="risk",  # Size by Risk Score
            size_max=15,
            hover_name="ssid",
            hover_data={"lat": False, "lon": False, "bssid": True, "security": True, "risk": True},
            color_continuous_scale=["#00dbde", "#ff0844"], # Cyan -> Red
            mapbox_style="carto-darkmatter",
             zoom=12,
        )
        
        fig.update_layout(**layout_override)
        if hasattr(fig, 'update_coloraxes'):
            fig.update_coloraxes(showscale=False)
            
        return fig

    except Exception as e:
        print(f"Map Error: {e}")
        fig = go.Figure(go.Scattermapbox())
        fig.update_layout(**layout_override)
        return fig
