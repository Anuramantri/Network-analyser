import re
import numpy as np
from pyvis.network import Network
from collections import defaultdict
import random  # Needed for selecting one timeout node

def select_main_node(hop):
    stats = defaultdict(lambda: {'rtt': float('inf'), 'success': 0, 'count': 0})
    for entry in hop:
        ip = entry['ip']
        if ip == "*" or ip.startswith("Unknown (timeout_"):
            continue
        stats[ip]['success'] += entry.get('success', 0)
        stats[ip]['count'] += 1
        if entry['rtt'] is not None:
            stats[ip]['rtt'] = min(stats[ip]['rtt'], entry['rtt'])

    max_count = max((stats[ip]['count'] for ip in stats), default=0)
    candidates = [ip for ip in stats if stats[ip]['count'] == max_count and max_count > 1]

    if not candidates:
        candidates = list(stats.keys())

    if not candidates:
        return None

    max_success = max((stats[ip]['success'] for ip in candidates), default=0)
    candidates = [ip for ip in candidates if stats[ip]['success'] == max_success]

    return min(candidates, key=lambda ip: stats[ip]['rtt'])

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
    probe_count = 0
    hop_index = -1

    while i < len(lines):
        line = lines[i]

        hop_match = re.match(r"Hop (\d+):", line)
        if hop_match:
            if current_hop:
                hops.append(current_hop)
            current_hop = []
            hop_index = int(hop_match.group(1))
            probe_count = 0
            i += 1
            continue

        timeout_match = re.match(r"\s+Probe (\d+): \* Request timed out", line)
        if timeout_match:
            probe_number = timeout_match.group(1)
            label = f"Timed out (Hop {hop_index}, Probe {probe_number})"
            current_hop.append({
                "ip": label,
                "rtt": None,
                "bw": None,
                "jitter": None,
                "success": 0
            })
            i += 1
            probe_count += 1
            continue

        probe_match = re.match(
            r"\s+Probe (\d+): ([\d\.]+) \| RTT: ([\d\.]+) ms \| BW: ([\d\.NA/]+) ?(?:Mbps)? \| Jitter: ([\d\.NA/]+) ?(?:ms)? \| Average RTT:([\d\.NA/]+) ?(?:ms)?(?:\s*\| Successful probes\(/10\):(\d+))?",
            line
        )

        if probe_match:
            probe_number, ip, rtt, bw, jitter, avg_rtt, success = probe_match.groups()
            if success is None:
                next_line = lines[i + 1] if i + 1 < len(lines) else ""
                success_match = re.search(r"Successful probes\(/10\):(\d+)", next_line)
                if success_match:
                    success = success_match.group(1)
                    i += 1

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
            probe_count += 1
            continue

        i += 1

    if current_hop:
        hops.append(current_hop)

    return hops, dest_ip

def compute_bandwidth_bins(hops):
    all_bw = [entry['bw'] for hop in hops for entry in hop if entry['bw'] is not None]
    quantiles = np.quantile(all_bw, [0.33, 0.66]) if all_bw else [0, 0]
    return quantiles

def get_color(bw, is_source, quantiles, is_timeout):
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
    main_nodes = []

    if dest_ip:
        dest_ip = dest_ip.strip()

    for hop_index, hop in enumerate(hops):
        curr_ips = set()
        for entry in hop:
            ip = entry['ip']
            is_timeout = ip.startswith("Timed out")

            if ip not in node_info:
                title = f"IP: {ip}\nRTT: {entry['rtt']} ms\nBW: {entry['bw']} Mbps\nJitter: {entry['jitter']} ms"
                color = get_color(entry['bw'], (hop_index == 0 or dest_ip == ip), quantiles, is_timeout)
                net.add_node(ip, label=ip, title=title, color=color)
                node_info[ip] = {"entry": entry}
            else:
                # If the IP already exists, update the stored values if the new ones are lower.
                stored = node_info[ip]["entry"]
            
                if entry['bw'] is not None and (stored['bw'] is None or entry['bw'] < stored['bw']):
                    stored['bw'] = entry['bw']
                    stored['rtt'] = entry['rtt'] 
                    stored['jitter'] = entry['jitter']                    
                    
                updated_title = f"IP: {ip}\nRTT: {stored['rtt']} ms\nBW: {stored['bw']} Mbps\nJitter: {stored['jitter']} ms"
                updated_color = get_color(stored['bw'], (hop_index == 0 or dest_ip == ip), quantiles, is_timeout)
                
                for node in net.nodes:
                    if node["id"] == ip:
                        node["title"] = updated_title
                        node["color"] = updated_color
                        break

                node_info[ip]["entry"] = stored

            curr_ips.add(ip)

        if hop_index > 0:
            main_prev_ip = select_main_node(hops[hop_index - 1])
            if main_prev_ip is None:
                # If all previous nodes were timeouts, pick one randomly
                timeout_candidates = [entry['ip'] for entry in hops[hop_index - 1] if entry['ip'].startswith("Timed out")]
                if timeout_candidates:
                    main_prev_ip = random.choice(timeout_candidates)
                else:
                    continue
            main_nodes.append(main_prev_ip)

            for curr_ip in curr_ips:
                if ((main_prev_ip, curr_ip) not in added_edges) and (main_prev_ip != curr_ip):
                    net.add_edge(main_prev_ip, curr_ip)
                    added_edges.add((main_prev_ip, curr_ip))

    bottleneck_node = None
    min_bw = float('inf')
    for ip in main_nodes:
        if ip is None:
            continue
        if ip not in node_info:
            continue
        entry = node_info.get(ip, {}).get("entry", {})
        bw = entry.get("bw")
        if bw is not None and bw < min_bw:
            min_bw = bw
            bottleneck_node = ip

    # Highlight the bottleneck node if found
    if bottleneck_node:
        net.nodes = [
            {**node, **{
                "color": "white",
                "size": 25,
                "borderWidth": 4,
                "title": f"[Bottleneck]\n{node.get('title', '')}"
            }} if node["id"] == bottleneck_node else node
            for node in net.nodes
        ]
    else:
        print("[INFO] No bottleneck node found.")


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
