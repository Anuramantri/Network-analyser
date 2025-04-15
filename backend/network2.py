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


def parse_traceroute(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()

    hops = []
    current_hop = []

    for line in lines:
        hop_match = re.match(r"Hop (\d+):", line)
        if hop_match:
            if current_hop:
                hops.append(current_hop)
                current_hop = []
            continue

        # Updated regex to support "N/A" without units
        probe_match = re.match(
            r"\s+Probe \d+: ([\d\.]+) \| RTT: ([\d\.]+) ms \| BW: ([\d\.NA/]+) ?(?:Mbps)? \| Jitter: ([\d\.NA/]+) ?(?:ms)? \| Successful probes\(/10\):(\d+)",
            line
        )

        if probe_match:
            ip, rtt, bw, jitter, success = probe_match.groups()
            bw = None if bw == "N/A" else float(bw)
            jitter = None if jitter == "N/A" else float(jitter)
            current_hop.append({
                "ip": ip,
                "rtt": float(rtt),
                "bw": bw,
                "jitter": jitter,
                "success": int(success)
            })


    if current_hop:
        hops.append(current_hop)

    return hops



def compute_bandwidth_bins(hops):
    all_bw = [entry['bw'] for hop in hops for entry in hop if entry['bw'] is not None]
    quantiles = np.quantile(all_bw, [0.33, 0.66]) if all_bw else [0, 0]
    return quantiles

def get_color(bw, is_source, quantiles):
    if is_source:
        return 'blue'
    if bw is None:
        return 'gray'
    if bw <= quantiles[0]:
        return 'red'
    elif bw <= quantiles[1]:
        return 'yellow'
    else:
        return 'green'


def build_graph(hops,output_file="network_topology.html"):
    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    node_info = {}
    quantiles = compute_bandwidth_bins(hops)
    added_edges = set()

    prev_ips = set()
    for hop_index, hop in enumerate(hops):
        curr_ips = set()
        for entry in hop:
            ip = entry['ip']
            if ip not in node_info:
                title = f"IP: {ip}\nRTT: {entry['rtt']} ms\nBW: {entry['bw']} Mbps\nJitter: {entry['jitter']} ms"
                color = get_color(entry['bw'], hop_index == 0, quantiles)
                net.add_node(ip, label=ip, title=title, color=color)
                node_info[ip] = True
            curr_ips.add(ip)

        # Connect previous hop to current hop
      
        if hop_index > 0:
            main_prev_ip = select_main_node(hops[hop_index - 1])
            for curr_ip in curr_ips:
                if (main_prev_ip, curr_ip) not in added_edges:
                    net.add_edge(main_prev_ip, curr_ip)
                    added_edges.add((main_prev_ip, curr_ip))

        # main_path_edges = []
        # for i in range(1, len(hops)):
        #     main_prev_ip = select_main_node(hops[i - 1])
        #     main_curr_ip = select_main_node(hops[i])
        #     # Compute the average BW for the main node in the current hop (if available)
        #     bw_values = [entry['bw'] for entry in hops[i] if entry['ip'] == main_curr_ip and entry['bw'] is not None]
        #     # If there is no available BW value, use a very high number so it isn't treated as the bottleneck.
        #     avg_bw = sum(bw_values) / len(bw_values) if bw_values else float('inf')
        #     main_path_edges.append((main_prev_ip, main_curr_ip, avg_bw))
        
        # # Find the edge with the minimum average bandwidth
        # if main_path_edges:
        #     bottleneck_edge = min(main_path_edges, key=lambda x: x[2])
        #     bottleneck_src, bottleneck_dst, _ = bottleneck_edge
        #     # Add an extra edge with glowing attributes (or re-add it to override default styling).
        #     net.add_edge(
        #         bottleneck_src,
        #         bottleneck_dst,
        #         color="cyan",
        #         width=5,
        #         title="Bottleneck Link (Lowest Bandwidth)"
        #     )


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


if __name__ == "__main__":
    hops = parse_traceroute("traceroute_output.txt")
    build_graph(hops)
