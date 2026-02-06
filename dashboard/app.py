
import os

import dash
import dash_auth
import dash_bootstrap_components as dbc
from dash import dcc, html
from flask import Flask

from dashboard.components.sidebar import sidebar

# Initialize Flask
server = Flask(__name__)

# Initialize Dash with Pages support
app = dash.Dash(
    __name__,
    server=server,
    use_pages=True, # Enable Multi-Page App
    url_base_pathname="/dashboard/",
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap",
        "https://use.fontawesome.com/releases/v6.0.0/css/all.css",
    ],
    suppress_callback_exceptions=True,
    title="Sentinel NetLab",
)

# Configuration
API_TOKEN = os.environ.get("DASHBOARD_API_TOKEN", "")

# Security
from common.security.secrets import require_secret  # noqa: E402

env = os.getenv("ENVIRONMENT", "production").lower()

_username = require_secret(
    "Dashboard Username",
    "DASH_USERNAME",
    min_len=4,
    allow_dev_autogen=False,
    env=env
)

_password = require_secret(
    "Dashboard Password",
    "DASH_PASSWORD",
    min_len=8,
    allow_dev_autogen=False,
    env=env
)

VALID_USERNAME_PASSWORD_PAIRS = {_username: _password}
auth = dash_auth.BasicAuth(app, VALID_USERNAME_PASSWORD_PAIRS)


# Main Layout
app.layout = html.Div(
    [
        dcc.Location(id="url"),
        sidebar,
        dash.page_container, # Pages are rendered here
    ]
)

if __name__ == "__main__":
    host = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.getenv("DASHBOARD_PORT", "8050"))
    debug_mode = os.getenv("DASH_DEBUG", "true").lower() == "true"
    app.run(debug=debug_mode, host=host, port=port)
