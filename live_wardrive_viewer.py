import json
import logging
from pathlib import Path
import traceback

import dash
from dash import dcc, html, Input, Output, dash_table
import pandas as pd
import plotly.express as px

# Configuration
DATA_FILE = "wardrive_session.json"
UPDATE_INTERVAL_MS = 3000  # Reload every 3 seconds

# Setup minimal logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Initialize Dash App
app = dash.Dash(__name__, title="Sentinel Live Wardrive Viewer")

# Define layout
app.layout = html.Div([
    html.H1("🛰️ Sentinel Live Wardrive Viewer", style={"textAlign": "center"}),

    # Auto-refresh timer
    dcc.Interval(
        id="interval-component",
        interval=UPDATE_INTERVAL_MS,
        n_intervals=0
    ),

    # Summary stats row
    html.Div([
        html.Div([
            html.H3("Total Unique Networks"),
            html.H2(id="stat-unique-networks", style={"color": "#007bff"})
        ], style={"width": "30%", "display": "inline-block", "textAlign": "center"}),

        html.Div([
            html.H3("Total Sightings"),
            html.H2(id="stat-total-sightings", style={"color": "#28a745"})
        ], style={"width": "30%", "display": "inline-block", "textAlign": "center"}),

        html.Div([
            html.H3("Last Update"),
            html.H4(id="stat-last-update", style={"color": "#6c757d"})
        ], style={"width": "30%", "display": "inline-block", "textAlign": "center"}),
    ], style={"marginBottom": "20px", "marginTop": "20px"}),

    # Map and Bar Chart row
    html.Div([
        html.Div([
            dcc.Graph(id="live-map")
        ], style={"width": "65%", "display": "inline-block", "verticalAlign": "top"}),

        html.Div([
            dcc.Graph(id="security-bar-chart")
        ], style={"width": "33%", "display": "inline-block", "verticalAlign": "top"})
    ]),

    # Data Table row
    html.Div([
        html.H3("10 Newest Networks Captured"),
        dash_table.DataTable(
            id="recent-networks-table",
            columns=[
                {"name": "Timestamp", "id": "timestamp"},
                {"name": "BSSID", "id": "bssid"},
                {"name": "SSID", "id": "ssid"},
                {"name": "RSSI (dBm)", "id": "rssi_dbm"},
                {"name": "Channel", "id": "channel"},
                {"name": "Security", "id": "security"},
            ],
            style_table={"overflowX": "auto"},
            style_cell={"textAlign": "left", "padding": "5px"},
            style_header={"backgroundColor": "#f8f9fa", "fontWeight": "bold"},
        )
    ], style={"marginTop": "20px", "padding": "0 20px"}),

    html.Div(id="error-msg", style={"color": "red", "textAlign": "center", "marginTop": "20px"})
])


def load_data():
    """Safely loads and parses the wardrive JSON file."""
    filepath = Path(DATA_FILE)
    if not filepath.exists():
        return None, "File not found. Please ensure the sensor is running and writing to wardrive_session.json."

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data, None
    except json.JSONDecodeError:
        # File might be mid-write; ignore and wait for next interval
        logging.warning("JSON Decode Error - file might be mid-write. Skipping this interval.")
        return None, "Reading file... (mid-write)"
    except Exception as e:
        err = f"Error reading data: {str(e)}"
        logging.error(err)
        return None, err


@app.callback(
    [
        Output("stat-unique-networks", "children"),
        Output("stat-total-sightings", "children"),
        Output("stat-last-update", "children"),
        Output("live-map", "figure"),
        Output("security-bar-chart", "figure"),
        Output("recent-networks-table", "data"),
        Output("error-msg", "children"),
    ],
    [Input("interval-component", "n_intervals")]
)
def update_dashboard(n):
    data, error = load_data()

    # Default empty states
    empty_fig = px.scatter()
    empty_bar = px.bar()

    if error and not data:
        if "(mid-write)" in error:
            # Prevent updating the UI if we're mid-write to avoid flashing
            raise dash.exceptions.PreventUpdate
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, error

    if not data or "sightings" not in data:
        return "-", "-", "-", empty_fig, empty_bar, [], "Invalid data format."

    # Process Stats
    unique_nets = data.get("unique_networks", 0)
    total_sights = data.get("total_sightings", 0)
    last_update = data.get("start_time", "N/A")  # Update this if there's a better last_update field

    sightings = data["sightings"]
    if not sightings:
        return unique_nets, total_sights, last_update, empty_fig, empty_bar, [], "No sightings yet."

    # Convert to DataFrame
    df = pd.DataFrame(sightings)

    # Extract lat/lon safely (ignoring sightings without valid GPS)
    if "gps" in df.columns:
        df["lat"] = df["gps"].apply(lambda x: x.get("lat") if isinstance(x, dict) else None)
        df["lon"] = df["gps"].apply(lambda x: x.get("lon") if isinstance(x, dict) else None)
    else:
        df["lat"] = None
        df["lon"] = None

    # Filter out rows with missing GPS for the map
    df_map = df.dropna(subset=["lat", "lon"]).copy()

    # --- 1. Live Map ---
    # To color by RSSI instead of Security, change `color="security"` to `color="rssi_dbm"`
    if not df_map.empty:
        fig_map = px.scatter_mapbox(
            df_map,
            lat="lat",
            lon="lon",
            color="security",  # Change to rssi_dbm if preferred
            hover_name="ssid",
            hover_data=["bssid", "rssi_dbm", "channel", "security"],
            zoom=14,
            height=500,
            title="Wardrive Map (Colored by Security)"
        )
        fig_map.update_layout(mapbox_style="open-street-map")
        fig_map.update_layout(margin={"r": 0, "t": 40, "l": 0, "b": 0})
    else:
        fig_map = empty_fig

    # --- 2. Security Bar Chart ---
    if "security" in df.columns:
        sec_counts = df["security"].value_counts().reset_index()
        sec_counts.columns = ["Security Type", "Count"]
        fig_bar = px.bar(
            sec_counts,
            x="Security Type",
            y="Count",
            color="Security Type",
            title="Networks by Security Standard",
            height=500
        )
    else:
        fig_bar = empty_bar

    # --- 3. Data Table (Top 10 Newest) ---
    # Sort by timestamp descending
    if "timestamp" in df.columns:
        df_sorted = df.sort_values(by="timestamp", ascending=False)
    else:
        df_sorted = df

    # Get top 10 and format for DataTable
    top_10 = df_sorted.head(10).copy()

    # Drop nested complex objects (like 'gps' dict) for table display
    if "gps" in top_10.columns:
        top_10 = top_10.drop(columns=["gps"])

    table_data = top_10.to_dict("records")

    # Use the most recent timestamp as last update if available
    if "timestamp" in df_sorted.columns and not df_sorted.empty:
        last_update = df_sorted.iloc[0]["timestamp"]

    return unique_nets, total_sights, last_update, fig_map, fig_bar, table_data, ""


if __name__ == "__main__":
    print("="*60)
    print("  Starting Live Wardrive Viewer...")
    print("  Ensure you have installed dependencies:")
    print("  pip install dash pandas plotly")
    print("  ")
    print("  Looking for file: wardrive_session.json")
    print("="*60)

    # Run server locally
    app.run(debug=True, port=8050, use_reloader=False)
