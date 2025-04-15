import networkx as nx
from pyvis.network import Network
import os
import re
from collections import defaultdict
import numpy as np

def parse_traceroute(filename):
    results = []
    current_ip = None
    hop = 1

    with open(filename, 'r') as file:
        for line in file:
            # Handle timeouts
            if "Probe 1:" in line:
                if "* Request timed out" in line:
                    current_ip = None  # clear stale IP
                else:
                    match_ip = re.search(r"Probe 1:\s+([\d\.]+)", line)
                    if match_ip:
                        current_ip = match_ip.group(1)

            if "[Stats]" in line and current_ip:
                match_stats = re.search(
                    r"Avg RTT:\s+([\d\.]+)\s+ms\s+\|\s+Jitter:\s+([\d\.]+)\s+ms\s+\|\s+Avg BW:\s+([\d\.]+)\s+Mbps",
                    line
                )
                if match_stats:
                    try:
                        avg_rtt = float(match_stats.group(1))
                        jitter = float(match_stats.group(2))
                        avg_bw = float(match_stats.group(3))

                        results.append((hop, current_ip, avg_rtt, jitter, avg_bw))
                        hop += 1
                        current_ip = None  # reset after use
                    except Exception as e:
                        print(f"[!] Parsing error: {line.strip()} ({e})")
    return results


def add_zoom_constraints(html_file: str, min_zoom: float = 0.3, max_zoom: float = 2.0, drag_bounds: int = 1000):
    """
    Injects zoom and drag constraints into the network visualization HTML.
    """
    with open(html_file, "r", encoding="utf-8") as f:
        html = f.read()

    js_constraints = f"""
    <script type="text/javascript">
      network.on("beforeDrawing", function() {{
        var scale = network.getScale();
        if (scale < {min_zoom}) {{
          network.moveTo({{scale: {min_zoom}}});
        }} else if (scale > {max_zoom}) {{
          network.moveTo({{scale: {max_zoom}}});
        }}
        var pos = network.getViewPosition();
        var clampedX = Math.max(Math.min(pos.x, {drag_bounds}), -{drag_bounds});
        var clampedY = Math.max(Math.min(pos.y, {drag_bounds}), -{drag_bounds});
        if (clampedX !== pos.x || clampedY !== pos.y) {{
          network.moveTo({{position: {{x: clampedX, y: clampedY}}, scale: scale}});
        }}
      }});
    </script>
    </body>
    """
    html = html.replace("</body>", js_constraints)

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)

def add_legend_to_html(html_file, bins, colors):
    legend_html = """
    <div id="legend" style="
        position: fixed;
        bottom: 20px;
        left: 20px;
        background: rgba(0, 0, 0, 0.7);
        color: white;
        padding: 10px;
        font-family: Tahoma, sans-serif;
        font-size: 14px;
        border-radius: 8px;
        z-index: 999;
    ">
        <strong>Bandwidth Legend (Mbps)</strong><br>
    """

    for i in range(len(bins) - 1):
        legend_html += f"""
            <div style="margin-top: 4px;">
                <span style="display:inline-block; width:16px; height:16px; background:{colors[i]}; margin-right:8px; border-radius:3px;"></span>
                {bins[i]:.2f} - {bins[i+1]:.2f}
            </div>
        """

    legend_html += "</div>\n</body>"

    # Inject legend before </body>
    with open(html_file, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</body>", legend_html)

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)

def create_network_visualization(traceroute_data):
    G = nx.DiGraph()
    nodes = ["Source"]
    traceroute_data.sort()

    # Create nodes with attributes.
    for hop, ip, rtt, jitter, bw in traceroute_data:
        nodes.append(ip)
        G.add_node(
            ip,
            title=f"IP: {ip}\nRTT: {rtt} ms\nJitter: {jitter} ms\nBandwidth: {bw} Mbps",
            rtt=rtt,
            jitter=jitter,
            bandwidth=bw
        )

    # Add a "Source" node (if needed, customize its attributes)
    G.add_node("Source", title="Source", rtt=0, jitter=0, bandwidth=None)

    # Add directed edges between consecutive hops
    for i in range(len(nodes) - 1):
        G.add_edge(nodes[i], nodes[i + 1])

    # Create a Pyvis network.
    net = Network(notebook=False, cdn_resources="in_line",
                  bgcolor="#222222", font_color="white",
                  height="750px", width="100%")

    net.set_options("""
    {
    "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "font": {
          "size": 20,
          "face": "Tahoma"
        }
    },
    "edges": {
        "color": {
        "inherit": true
        }
    },
    "physics": {
        "enabled": false
    }
    }
    """)

    # Determine bandwidth bins for coloring nodes.
    bw_values = [attrs['bandwidth'] for _, attrs in G.nodes(data=True) if attrs.get('bandwidth') is not None]
    if bw_values:
        bins = np.quantile(bw_values, [0, 0.33, 0.66, 1.0])
    else:
        bins = [0, 3000, 7000, 10000]  # fallback default

    colors = ["#ff0000", "#ffaa00", "#00ff00"]
    
    # Add nodes to the Pyvis network with color based on bandwidth.
    for node, attrs in G.nodes(data=True):
        if attrs.get('bandwidth') is not None:
            bw = attrs['bandwidth']
            # Determine color based on the bandwidth bin.
            if bw <= bins[1]:
                color = colors[0]  # low
            elif bw <= bins[2]:
                color = colors[1]  # medium
            else:
                color = colors[2]   # high

            size = 20
            net.add_node(
                node,
                label=node,
                title=attrs['title'],
                color=color,
                size=size
            )
        else:
            # Define the source node.
            net.add_node(node, label=node, title=node, color="#6AAFFF", size=20)

    # Compute edge attributes: Use the bandwidth of the destination node.
    edge_data = []
    for i in range(1, len(nodes)):
        target = nodes[i]
        bw = G.nodes[target].get("bandwidth")
        if bw is not None:
            edge_data.append(((nodes[i-1], nodes[i]), bw))
    
    # Identify the bottleneck edge (minimum bandwidth)
    if edge_data:
        bottleneck_edge = min(edge_data, key=lambda x: x[1])[0]
    else:
        bottleneck_edge = None

    # Add edges with the title attribute showing bandwidth and special styling for the bottleneck edge.
    for i in range(1, len(nodes)):
        source = nodes[i-1]
        target = nodes[i]
        # Retrieve bandwidth from the destination node.
        bw = G.nodes[target].get("bandwidth", "N/A")
        title_text = f"BW: {bw} Mbps"
        if bottleneck_edge is not None and (source, target) == bottleneck_edge:
            # Bottleneck edge: highlight in white with thicker width.
            net.add_edge(source, target, title=title_text, color="white", width=6)
        else:
            net.add_edge(source, target, title=title_text)
    
    html_file = "network_topology.html"
    net.save_graph(html_file)

    add_zoom_constraints(html_file)
    add_legend_to_html(html_file, bins, colors)

    return html_file
