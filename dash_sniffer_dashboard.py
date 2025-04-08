import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.express as px
import plotly.graph_objs as go
from collections import Counter, defaultdict
from datetime import datetime
import threading
from scapy.all import sniff

# ------------------ CONFIG ------------------
PACKET_LIMIT = 100
LIVE_INTERVAL_MS = 1000

# ------------------ GLOBAL STATE ------------------
packet_data = []
protocol_counter = Counter()
protocol_over_time = defaultdict(list)
time_series = []

# ------------------ PACKET HANDLER ------------------
def packet_callback(packet):
    summary = packet.summary()
    proto = summary.split()[0]
    now = datetime.now()
    timestamp = now.strftime('%H:%M:%S')

    packet_data.append({
        "timestamp": timestamp,
        "protocol": proto,
        "datetime": now
    })

    protocol_counter[proto] += 1
    protocol_over_time[proto].append((timestamp, protocol_counter[proto]))
    time_series.append((timestamp, proto))

# ------------------ SNIFF THREAD ------------------
def start_sniffing():
    sniff(prn=packet_callback, count=PACKET_LIMIT, store=False)

sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
sniffer_thread.start()

# ------------------ DASH APP ------------------
app = dash.Dash(__name__)
app.title = "Live Packet Sniffer Dashboard"

app.layout = html.Div([
    html.H1("📡 Ultimate Packet Sniffer Dashboard", style={"textAlign": "center"}),

    html.Div([
        dcc.Graph(id='bar-chart'),
        dcc.Graph(id='pie-chart'),
        dcc.Graph(id='line-chart'),
    ], style={'display': 'flex', 'flexWrap': 'wrap'}),

    html.Div([
        dcc.Graph(id='histogram'),
        dcc.Graph(id='stacked-timeline'),
    ], style={'display': 'flex', 'flexWrap': 'wrap'}),

    html.H2("📋 Protocol Table", style={"textAlign": "center"}),
    dash_table.DataTable(
        id='protocol-table',
        columns=[
            {"name": "Protocol", "id": "Protocol"},
            {"name": "Count", "id": "Count"}
        ],
        style_table={'overflowX': 'auto', 'width': '50%', 'margin': 'auto'},
        style_cell={'textAlign': 'center', 'padding': '6px'},
        style_header={'backgroundColor': '#f2f2f2', 'fontWeight': 'bold'}
    ),

    dcc.Interval(id='interval-component', interval=LIVE_INTERVAL_MS, n_intervals=0)
])

@app.callback(
    Output('bar-chart', 'figure'),
    Output('pie-chart', 'figure'),
    Output('line-chart', 'figure'),
    Output('histogram', 'figure'),
    Output('stacked-timeline', 'figure'),
    Output('protocol-table', 'data'),
    Input('interval-component', 'n_intervals')
)
def update_graph(n):
    if not packet_data:
        empty_fig = go.Figure()
        empty_fig.update_layout(title="Waiting for Packets...")
        return empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, []

    # Protocol Count Bar Chart
    labels = list(protocol_counter.keys())
    values = list(protocol_counter.values())
    bar_fig = px.bar(x=labels, y=values, labels={"x": "Protocol", "y": "Count"}, title="Protocol Count")

    # Pie Chart
    pie_fig = px.pie(names=labels, values=values, title="Protocol Distribution")

    # Line Chart - Protocol Over Time
    line_fig = go.Figure()
    for proto, pts in protocol_over_time.items():
        x = [p[0] for p in pts]
        y = [p[1] for p in pts]
        line_fig.add_trace(go.Scatter(x=x, y=y, mode='lines+markers', name=proto))
    line_fig.update_layout(title="Protocol Trend Over Time")

    # Histogram
    first_time = packet_data[0]["datetime"]
    intervals = [(pkt["datetime"] - first_time).total_seconds() for pkt in packet_data]
    hist_fig = px.histogram(x=intervals, nbins=15, labels={"x": "Seconds since start"}, title="Packet Arrival Time")

    # Stacked Timeline
    timeline_data = defaultdict(lambda: defaultdict(int))
    for t, proto in time_series:
        timeline_data[t][proto] += 1
    timestamps = sorted(timeline_data.keys())
    stacked_fig = go.Figure()
    for proto in labels:
        y = [timeline_data[t][proto] for t in timestamps]
        stacked_fig.add_trace(go.Bar(x=timestamps, y=y, name=proto))
    stacked_fig.update_layout(barmode='stack', title="Stacked Protocol Timeline")

    # Table Data
    table_data = [{"Protocol": proto, "Count": count} for proto, count in protocol_counter.items()]

    return bar_fig, pie_fig, line_fig, hist_fig, stacked_fig, table_data

if __name__ == '__main__':
    app.run_server(debug=True, port=8051, host='0.0.0.0')

