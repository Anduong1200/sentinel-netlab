from dash import html

# --- Styling Constants ---
COLOR_PRIMARY = "#00f2fe"
GLASS_STYLE = {
    "background": "rgba(20, 20, 35, 0.4)",
    "backdropFilter": "blur(12px)",
    "WebkitBackdropFilter": "blur(12px)",
    "border": "1px solid rgba(255, 255, 255, 0.08)",
    "borderRadius": "16px",
    "boxShadow": "0 8px 32px 0 rgba(0, 0, 0, 0.3)",
}


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
