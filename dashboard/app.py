import dash
from dash import dcc, html, Input, Output
import dash_bootstrap_components as dbc
from flask import Flask
import requests
import plotly.express as px
import pandas as pd
import os

# Initialize Flask (wrapped by controller or standalone)
server = Flask(__name__)

# Initialize Dash
app = dash.Dash(
    __name__,
    server=server,
    url_base_pathname='/dashboard/',
    external_stylesheets=[dbc.themes.DARKLY]
)

# Configuration from env or defaults
CONTROLLER_API = os.environ.get('CONTROLLER_URL', 'http://localhost:5000')

# Layout
app.layout = html.Div([
    dbc.NavbarSimple(
        brand="Sentinel NetLab - Sentinel Dashboard",
        brand_href="#",
        color="primary",
        dark=True,
        className="mb-4"
    ),
    
    dbc.Container([
        dbc.Row([
            dbc.Col([
                html.H2("Operational Status", className="mb-3"),
                dbc.Card([
                    dbc.CardBody([
                        html.H4("Active Sensors", className="card-title"),
                        html.H1("0", id="sensor-count", className="text-success")
                    ])
                ], className="mb-4")
            ], width=4),
            
            dbc.Col([
                html.H2("Risk Overview", className="mb-3"),
                dbc.Card([
                    dbc.CardBody([
                        html.H4("Critical Alerts", className="card-title"),
                        html.H1("0", id="alert-count", className="text-danger")
                    ])
                ], className="mb-4")
            ], width=4),
            
            dbc.Col([
                html.H2("System", className="mb-3"),
                dbc.Card([
                    dbc.CardBody([
                        html.H4("Mode", className="card-title"),
                        html.H3("WIDS + Assessment", className="text-info")
                    ])
                ], className="mb-4")
            ], width=4),
        ]),
        
        dbc.Row([
            dbc.Col([
                html.H3("Wardriving Heatmap (GPS)", className="mb-3"),
                dcc.Loading(
                    dcc.Graph(id='heatmap-graph', style={'height': '500px'})
                )
            ], width=12, className="mb-5")
        ]),
        
        dbc.Row([
            dbc.Col([
                html.H3("Recent Security Alerts", className="mb-3"),
                html.Div(id='alerts-table')
            ], width=12)
        ]),
        
        dcc.Interval(
            id='interval-component',
            interval=10*1000, # 10 seconds
            n_intervals=0
        )
    ], fluid=True)
])

@app.callback(
    [Output('heatmap-graph', 'figure'),
     Output('sensor-count', 'children'),
     Output('alert-count', 'children'),
     Output('alerts-table', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_metrics(n):
    # Default outputs
    empty_map = px.scatter_mapbox(
        pd.DataFrame({'lat': [], 'lon': []}), 
        lat='lat', lon='lon', 
        mapbox_style="carto-darkmatter",
        zoom=0
    )
    empty_map.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
    
    try:
        # 1. Get Wardriving/Network Data
        resp_net = requests.get(f"{CONTROLLER_API}/api/v1/networks", timeout=2)
        networks = resp_net.json().get('networks', []) if resp_net.status_code == 200 else []
        
        # 2. Get Alerts
        resp_alerts = requests.get(f"{CONTROLLER_API}/api/v1/alerts", timeout=2)
        alerts = resp_alerts.json().get('alerts', []) if resp_alerts.status_code == 200 else []
        
        # Process Map
        if networks:
            # Filter for nets with GPS
            data = [
                {
                    'lat': n.get('lat', 0), 
                    'lon': n.get('lon', 0), 
                    'ssid': n.get('ssid', 'Unknown'),
                    'risk': n.get('risk_score', 0)
                } 
                for n in networks if n.get('lat')
            ]
            
            if data:
                df = pd.DataFrame(data)
                fig = px.density_mapbox(
                    df, lat='lat', lon='lon', z='risk',
                    radius=20,
                    center=dict(lat=df.lat.mean(), lon=df.lon.mean()),
                    zoom=13,
                    mapbox_style="carto-darkmatter"
                )
                fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
            else:
                fig = empty_map
        else:
            fig = empty_map
            
        # Process Alerts Table
        if alerts:
            table_header = [
                html.Thead(html.Tr([html.Th("Time"), html.Th("Severity"), html.Th("Message"), html.Th("Recommendation")]))
            ]
            rows = []
            for a in alerts[:10]: # Top 10
                row_class = "table-danger" if a.get('severity') == 'CRITICAL' else "table-warning"
                rows.append(html.Tr([
                    html.Td(a.get('timestamp')),
                    html.Td(a.get('severity')),
                    html.Td(a.get('message')),
                    html.Td(a.get('recommendation'))
                ], className=row_class))
            
            table_body = [html.Tbody(rows)]
            table = dbc.Table(table_header + table_body, bordered=True, dark=True, hover=True, responsive=True)
        else:
            table = dbc.Alert("No active alerts detected.", color="success")
            
        return fig, str(len(set(n.get('sensor_id') for n in networks))), str(len(alerts)), table
        
    except Exception as e:
        print(f"Dashboard Update Error: {e}")
        return empty_map, "ERR", "ERR", dbc.Alert(f"Connection Error: {e}", color="danger")

if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)
