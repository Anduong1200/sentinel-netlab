
from dash import html
import dash_bootstrap_components as dbc

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
                    [html.I(className="fas fa-map nav-icon"), "Global Map"],
                    href="/dashboard/map",
                    active="exact",
                ),
                dbc.NavLink(
                    [html.I(className="fas fa-shield-alt nav-icon"), "Threat Matrix"],
                    href="/dashboard/threats",
                    active="exact",
                ),
                 dbc.NavLink(
                    [html.I(className="fas fa-wave-square nav-icon"), "Signal Analysis"],
                    href="/dashboard/signals",
                    active="exact",
                ),
                dbc.NavLink(
                    [html.I(className="fas fa-cogs nav-icon"), "Audit"],
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
