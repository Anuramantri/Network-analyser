import networkx as nx
from pyvis.network import Network
import re
from collections import defaultdict
import numpy as np
from collections import Counter


def parse_traceroute(log_text):
    hops = []
    current_hop = {}
    probe_data = []

    for line in log_text.splitlines():
        line = line.strip()
        if line.startswith("Hop"):
            if current_hop:
                current_hop["probes"] = probe_data
                hops.append(current_hop)
                probe_data = []
            current_hop = {"hop_num": int(re.search(r"Hop (\d+):", line).group(1))}

        elif line.startswith("Probe"):
            match = re.search(
                r"Probe (\d+): ([\d\.]+) \| RTT: ([\d\.]+) ms \| BW: ([\d\.]+) Mbps \| Successful probes\(/10\):(\d+)", 
                line
            )

            if match:
                probe_data.append({
                    "probe": int(match.group(1)),
                    "ip": match.group(2),
                    "rtt": float(match.group(3)),
                    "bw": float(match.group(4)),
                    "successful_probes": int(match.group(5))
                })

        elif line.startswith("[Stats]"):
            match = re.search(r"Avg RTT: ([\d\.]+) ms \| Jitter: ([\d\.]+) ms \| Avg BW: ([\d\.]+) Mbps", line)
            if match:
                current_hop["avg_rtt"] = float(match.group(1))
                current_hop["jitter"] = float(match.group(2))
                current_hop["avg_bw"] = float(match.group(3))

    if current_hop:
        current_hop["probes"] = probe_data
        hops.append(current_hop)

    print
    return hops

def create_network_visualization(traceroute_data):
    def select_main_ip(probes):
        ip_counts = Counter(p['ip'] for p in probes)
        ip_to_success = {}
        ip_to_rtt = {}

        for p in probes:
            ip = p['ip']
            ip_to_success[ip] = ip_to_success.get(ip, 0) + p.get('successful_probes', 0)
            ip_to_rtt[ip] = min(ip_to_rtt.get(ip, float('inf')), p['rtt'])

        # Step 1: most common IPs (appearing in 2 or more probes)
        filtered = [ip for ip, count in ip_counts.items() if count >= 2]
        candidates = filtered if filtered else list(ip_counts.keys())

        # Step 2: Max successful probes
        max_success = max(ip_to_success[ip] for ip in candidates)
        success_candidates = [ip for ip in candidates if ip_to_success[ip] == max_success]

        # Step 3: Min RTT
        best_ip = min(success_candidates, key=lambda ip: ip_to_rtt[ip])
        return best_ip

    G = nx.DiGraph()
    hop_ip_map = {}  # hop_num -> set of IPs
    all_nodes = set()
    bandwidths = []
    main_path = []

    # Build nodes and collect bandwidths
    for hop in traceroute_data:
        hop_num = hop['hop_num']
        ip_set = set()
        for probe in hop['probes']:
            ip = probe['ip']
            rtt = probe['rtt']
            bw = probe['bw']
            ip_set.add(ip)
            all_nodes.add(ip)
            G.add_node(
                ip,
                title=f"IP: {ip}\nRTT: {rtt} ms\nBandwidth: {bw} Mbps",
                rtt=rtt,
                bandwidth=bw
            )
            bandwidths.append(bw)
        hop_ip_map[hop_num] = list(ip_set)

        # Select main IP per hop
        main_ip = select_main_ip(hop['probes'])
        main_path.append(main_ip)

    # Build edges between IPs from consecutive hops
    sorted_hops = sorted(hop_ip_map.keys())
    for i in range(len(sorted_hops) - 1):
        curr_hop = sorted_hops[i]
        next_hop = sorted_hops[i + 1]
        curr_ips = hop_ip_map[curr_hop]
        next_ips = hop_ip_map[next_hop]

        main_src = main_path[i]
        main_dst = main_path[i + 1]

        for src in curr_ips:
            for dst in next_ips:
                is_main = (src == main_src and dst == main_dst)
                G.add_edge(src, dst, main=is_main)

    # Pyvis Network
    net = Network(
        notebook=False,
        cdn_resources="in_line",
        bgcolor="#222222",
        font_color="white",
        height="750px",
        width="100%"
    )

    # Set graph options
    net.set_options("""
    {
      "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "font": {
          "size": 15,
          "face": "Tahoma"
        }
      },
      "edges": {
        "color": {
          "inherit": true
        },
        "smooth": {
          "type": "continuous",
          "forceDirection": "none"
        }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -80000,
          "centralGravity": 0.3,
          "springLength": 250
        },
        "minVelocity": 0.75
      }
    }
    """)

    # Compute bandwidth bins
    if bandwidths:
        bins = np.quantile(bandwidths, [0, 0.33, 0.66, 1.0])
    else:
        bins = [0, 3000, 7000, 10000]  # fallback

    colors = ["#ff0000", "#ffaa00", "#00ff00"]  # red, orange, green

    # Add nodes with color logic
    for node, attrs in G.nodes(data=True):
        bw = attrs.get('bandwidth', 0)
        if bw <= bins[1]:
            color = colors[0]
        elif bw <= bins[2]:
            color = colors[1]
        else:
            color = colors[2]

        size = 20
        net.add_node(
            node,
            label=node,
            title=attrs.get('title', ''),
            color=color,
            size=size
        )

    # Add edges with styles
    for src, dst, attrs in G.edges(data=True):
        net.add_edge(src, dst, dashes=not attrs.get('main', False))


    html_file = "network_topology.html"
    net.save_graph(html_file)

    # Optional: add zoom/legend functions if defined elsewhere
    add_zoom_constraints(html_file)
    add_legend_to_html(html_file, bins, colors)

    return html_file


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

# with open("traceroute_output2.txt", "r") as f:
#     log_text = f.read()
#     traceroute_data = parse_traceroute(log_text)
#     create_network_visualization(traceroute_data)

#     net.set_options("""
# var options = {
#   "nodes": {
#     "borderWidth": 2,
#     "borderWidthSelected": 4,
#     "font": {
#       "size": 15,
#       "face": "Tahoma"
#     }
#   },
#   "edges": {
#     "color": {
#       "inherit": true
#     },
#     "smooth": {
#       "enabled": true,
#       "type": "dynamic"
#     }
#   },
#   "physics": {
#     "enabled": true,
#     "barnesHut": {
#       "gravitationalConstant": -20000,
#       "centralGravity": 0.3,
#       "springLength": 200,
#       "springConstant": 0.05,
#       "damping": 0.1,
#       "avoidOverlap": 1
#     },
#     "minVelocity": 0.5,
#     "solver": "barnesHut",
#     "timestep": 0.5
#   },
#   "interaction": {
#     "zoomView": true,
#     "dragView": true,
#     "dragNodes": true,
#     "multiselect": false,
#     "navigationButtons": true,
#     "keyboard": {
#       "enabled": false
#     }
#   },
#   "layout": {
#     "improvedLayout": true
#   },
#   "manipulation": false,
#   "configure": {
#     "enabled": false
#   }
# }
# """)

