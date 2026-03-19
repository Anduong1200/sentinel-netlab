import dash
import dash_bootstrap_components as dbc
import pandas as pd
from dash import html

from dashboard.components.cards import GLASS_STYLE

dash.register_page(__name__, path="/audit", title="Sentinel NetLab - Audit")

layout = html.Div(
    [
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.H4(
                            "System Audit Logs", className="fw-bold text-white mb-0"
                        ),
                        html.Span(
                            "Track administrative actions and node configurations",
                            className="text-muted small",
                        ),
                    ]
                )
            ),
            className="mb-4",
        ),
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.H5(
                            "Recent Audit Events", className="fw-bold text-white mb-3"
                        ),
                        dbc.Table.from_dataframe(
                            pd.DataFrame(
                                [
                                    {
                                        "Timestamp": "2026-03-18 10:00:00",
                                        "User/Node": "admin",
                                        "Action": "Lab Env Reset",
                                        "Status": "Success",
                                    },
                                    {
                                        "Timestamp": "2026-03-18 10:05:22",
                                        "User/Node": "sensor-wlan1",
                                        "Action": "Authentication",
                                        "Status": "Success",
                                    },
                                    {
                                        "Timestamp": "2026-03-18 10:15:40",
                                        "User/Node": "local-demo-sensor",
                                        "Action": "Telemetry Push",
                                        "Status": "Success",
                                    },
                                    {
                                        "Timestamp": "2026-03-18 11:22:15",
                                        "User/Node": "admin",
                                        "Action": "Export Report",
                                        "Status": "Processing",
                                    },
                                ]
                            ),
                            striped=True,
                            bordered=False,
                            hover=True,
                            className="text-white table-custom",
                        ),
                    ],
                    style=GLASS_STYLE,
                    className="p-3",
                ),
            )
        ),
    ],
    className="content",
)
