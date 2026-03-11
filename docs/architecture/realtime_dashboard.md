# Real-Time Dashboard Architecture

The Sentinel NetLab Dashboard provides a live window into your wireless environment. Rather than relying on heavy WebSockets or tightly coupled frontend frameworks, it uses a decoupled polling architecture built on **Dash (by Plotly)**.

## 1. The Decoupled Data Pipeline

The real-time nature of the dashboard is achieved through three distinct layers:

1. **Sensor Node (Producer)**: The `SensorController` continuously scoops packets from the air, analyzes them using the `RiskScorer` or `EvilTwinDetector`, and pushes compressed JSON telemetry batches to the Controller API every few seconds.
2. **Controller API (Buffer)**: The central server receives these batches and holds them in memory (or Redis). The API endpoints (`/api/v1/alerts`, `/api/v1/networks`) serve as lightning-fast read replicas.
3. **Dashboard UI (Consumer)**: The Dashboard is entirely stateless. It uses an invisible component called `dcc.Interval` to fire off asynchronous (AJAX) GET requests to the Controller API. When the data arrives, Dash automatically triggers Python callback functions to redraw the graphs without refreshing the browser page.

---

## 2. Tweaking the Refresh Rate (Speeding it up)

If you want the dashboard to feel more "alive" and responsive to immediate attacks (like a Deauth flood), you can lower the polling interval. 

By default, pages update every 5 to 15 seconds to save CPU. You can turbocharge this down to **2 seconds**.

**How to adjust:**
Open any page file (e.g., `dashboard/pages/overview.py`) and locate the `dcc.Interval` component near the bottom of the `layout` definition:

```python
        dcc.Interval(
            id="interval-component",
            interval=2000,  # <-- Change this value (in milliseconds). 2000 = 2 seconds.
            n_intervals=0,
        ),
```

> **Warning:** Setting the interval below 1000ms (1 second) may cause UI stuttering if the Controller API cannot respond fast enough or if the Plotly graphs require heavy rendering (like dense heatmaps).

---

## 3. Customizing Visuals and Theming

The Sentinel Dashboard avoids complex CSS files by relying on Dash Bootstrap Components (`dbc`) and Python dictionaries for styling.

### Changing the Color Palette (Dark/Light Mode)
The default theme is set in `dashboard/app.py`:
```python
    external_stylesheets=[
        dbc.themes.DARKLY, # Change to dbc.themes.FLATLY for a clean light mode
        # ...
    ]
```

### Tweaking Map Aesthetics
The `density_mapbox` (Heatmap) and standard map scatter plots are styled inside the `@callback` functions. You can change the map base layer to completely alter the vibe:
```python
    # Inside map.py or overview.py update functions
    layout_override = {
        "mapbox": {
            # Options: "carto-darkmatter", "open-street-map", "stamen-terrain", "stamen-watercolor", etc.
            "style": "carto-darkmatter", 
            "zoom": 12,
        },
    }
```

---

## 4. Expanding the Dashboard (Adding Analytics)

Because the entire dashboard is written in Python, you can easily add custom analytics panels if you know basic Pandas and Plotly.

**Example Workflow to add a "Vendor Tracking" Pie Chart:**

1. **Define the UI Slot**: In `dashboard/pages/overview.py`, add a new `dcc.Graph` component inside the layout grid.
   ```python
   dcc.Graph(id="vendor-pie-chart", style={"height": "300px"})
   ```
2. **Register the Output**: Add it to the `@callback` decorator.
   ```python
   @callback(
       [ ... existing outputs ...,
         Output("vendor-pie-chart", "figure") ] # Add your new output
   )
   def update_metrics(n):
   ```
3. **Crunch the Data & Draw**: Inside `update_metrics()`, parse the incoming JSON, group the data, and create a Plotly figure.
   ```python
        # Fake Example Logic inside update_metrics():
        vendor_fig = px.pie(
            df_networks, 
            names='vendor', 
            title="Hardware Manufacturers"
        )
        vendor_fig.update_layout(template="plotly_dark")
        
        return (..., vendor_fig) # Make sure the return tuple matches the Outputs above!
   ```
