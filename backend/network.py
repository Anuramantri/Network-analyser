import re
import numpy as np
from pyvis.network import Network
import re
from collections import defaultdict

def select_main_node(hop):
    stats = defaultdict(lambda: {'rtt': float('inf'), 'success': 0, 'count': 0})
    
    for entry in hop:
        ip = entry['ip']
        stats[ip]['success'] += entry.get('success', 0)
        stats[ip]['count'] += 1
        stats[ip]['rtt'] = min(stats[ip]['rtt'], entry['rtt'])

    max_count = max(stats[ip]['count'] for ip in stats)
    candidates = [ip for ip in stats if stats[ip]['count'] == max_count and max_count > 1]

    if not candidates:
        candidates = list(stats.keys())

    max_success = max(stats[ip]['success'] for ip in candidates)
    candidates = [ip for ip in candidates if stats[ip]['success'] == max_success]

    return min(candidates, key=lambda ip: stats[ip]['rtt'])


import re

def parse_traceroute(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()

    dest_ip = None
    first_line_match = re.match(r"Traceroute to .+ \(([\d\.]+)\)", lines[0])
    if first_line_match:
        dest_ip = first_line_match.group(1)

    hops = []
    current_hop = []

    i = 1
    while i < len(lines):
        line = lines[i]

        hop_match = re.match(r"Hop (\d+):", line)
        if hop_match:
            if current_hop:
                hops.append(current_hop)
                current_hop = []
            i += 1
            continue

        timeout_match = re.match(r"\s+Probe \d+: \* Request timed out", line)
        if timeout_match:
            current_hop.append({
                "ip": "*",
                "rtt": None,
                "bw": None,
                "jitter": None,
                "success": 0
            })
            i += 1
            continue

        # Probe line with optional success info on same line
        probe_match = re.match(
            r"\s+Probe \d+: ([\d\.]+) \| RTT: ([\d\.]+) ms \| BW: ([\d\.NA/]+) ?(?:Mbps)? \| Jitter: ([\d\.NA/]+) ?(?:ms)? \| Average RTT:([\d\.NA/]+) ?(?:ms)?(?:\s*\| Successful probes\(/10\):(\d+))?",
            line
        )

        if probe_match:
            ip, rtt, bw, jitter, avg_rtt, success = probe_match.groups()
            if success is None:
                # try to look at next line
                next_line = lines[i + 1] if i + 1 < len(lines) else ""
                success_match = re.search(r"Successful probes\(/10\):(\d+)", next_line)
                if success_match:
                    success = success_match.group(1)
                    i += 1  # skip the next line as it's consumed

            bw = None if bw == "N/A" else float(bw)
            jitter = None if jitter == "N/A" else float(jitter)

            current_hop.append({
                "ip": ip,
                "rtt": float(rtt),
                "bw": bw,
                "jitter": jitter,
                "success": int(success) if success else 0
            })

        i += 1

    if current_hop:
        hops.append(current_hop)

    return hops, dest_ip




def compute_bandwidth_bins(hops):
    all_bw = [entry['bw'] for hop in hops for entry in hop if entry['bw'] is not None]
    quantiles = np.quantile(all_bw, [0.33, 0.66]) if all_bw else [0, 0]
    return quantiles

def get_color(bw, is_source, quantiles,is_timeout):
    if is_source:
        return 'blue'
    if (bw is None) or is_timeout:
        return 'gray'
    if bw <= quantiles[0]:
        return 'red'
    elif bw <= quantiles[1]:
        return 'yellow'
    else:
        return 'green'


def build_graph(hops, output_file="network_topology.html", dest_ip=None):
    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    node_info = {}
    quantiles = compute_bandwidth_bins(hops)
    added_edges = set()

    if dest_ip:
        dest_ip = dest_ip.strip()

    for hop_index, hop in enumerate(hops):
        curr_ips = set()
        for entry in hop:
            ip = entry['ip']
            if ip not in node_info:
                # Handle timeouts separately
                is_timeout = ip == "*"
                if ip == "*":
                    ip = "Unknown (timeout)"
                title = f"IP: {ip}\nRTT: {entry['rtt']} ms\nBW: {entry['bw']} Mbps\nJitter: {entry['jitter']} ms"
                color = get_color(entry['bw'], (hop_index == 0 or dest_ip == ip), quantiles, is_timeout)
                net.add_node(ip, label=ip, title=title, color=color)
                node_info[ip] = True
            curr_ips.add(ip)

        # Connect previous hop to current hop
        if hop_index > 0:
            main_prev_ip = select_main_node(hops[hop_index - 1])
            if main_prev_ip is None:
                continue
            for curr_ip in curr_ips:
                if ((main_prev_ip, curr_ip) not in added_edges) and (main_prev_ip != curr_ip):
                    net.add_edge(main_prev_ip, curr_ip)
                    added_edges.add((main_prev_ip, curr_ip))

    # Add legend after rendering
    net.save_graph(output_file)

    legend_html = f"""
    <div style="
        position: fixed;
        bottom: 50px;
        left: 50px;
        background-color: rgba(255,255,255,0.9);
        padding: 10px;
        border-radius: 8px;
        font-size: 14px;
        font-family: monospace;
        z-index: 1000;
    ">
      <b>Bandwidth Legend (Mbps)</b><br>
      <span style="color:red;">⬤</span> ≤ {quantiles[0]:.2f}<br>
      <span style="color:orange;">⬤</span> ≤ {quantiles[1]:.2f}<br>
      <span style="color:green;">⬤</span> > {quantiles[1]:.2f}
    </div>
    """

    with open(output_file, "r") as f:
        html = f.read()
    html = html.replace("</body>", legend_html + "</body>")
    with open(output_file, "w") as f:
        f.write(html)

