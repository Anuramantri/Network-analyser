import networkx as nx
from pyvis.network import Network
import os
import re

def parse_traceroute_file(filename):
    """
    Reads traceroute output from a text file and extracts hop details.
    
    Returns:
        List of tuples (hop, ip_address, rtt, bandwidth)
    """
    traceroute_data = []
    with open(filename, 'r') as file:
        lines = file.readlines()

    parsing = False  # Flag to start parsing after header
    for line in lines:
        # Detect when hop data starts
        if "Hop\tIP Address" in line:
            parsing = True
            continue
        if "--- Network Statistics ---" in line:
            break  # Stop parsing at the stats section
        
        if parsing:
            match = re.match(r"(\d+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)", line)
            if match:
                hop = int(match.group(1))
                ip_address = match.group(2)
                rtt = float(match.group(3))
                bandwidth = float(match.group(4))
                traceroute_data.append((hop, ip_address, rtt, bandwidth))

    return traceroute_data

def create_network_visualization(traceroute_data):
    """
    Creates and displays a network visualization of traceroute data.
    
    Parameters:
    traceroute_data: List of tuples (hop, ip_address, rtt, bandwidth)
    """
    G = nx.DiGraph()

    # Create node list (starting with "Source")
    nodes = ["Source"]
    bandwidths = {}

    for hop, ip, rtt, bw in traceroute_data:
        nodes.append(ip)
        if bw > 0:
            bandwidths[ip] = bw

    # Add nodes with bandwidth attributes
    for node in nodes:
        if node in bandwidths:
            G.add_node(node, bandwidth=bandwidths[node], title=f"{node}: {bandwidths[node]} Mbps")
        else:
            G.add_node(node, title=node)

    # Add edges representing the path
    for i in range(len(nodes) - 1):
        G.add_edge(nodes[i], nodes[i + 1])

    # Create interactive visualization
    net = Network(notebook=False, cdn_resources="in_line",
                  bgcolor="#222222", font_color="white",
                  height="750px", width="100%")

    # Set visualization options
    net.set_options("""
    var options = {
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

    # Add nodes with color based on bandwidth
    for node, attrs in G.nodes(data=True):
        if 'bandwidth' in attrs:
            if attrs['bandwidth'] < 3000:
                color = "#ff0000"  # Red for bottleneck
            elif attrs['bandwidth'] < 7000:
                color = "#ffaa00"  # Orange for medium
            else:
                color = "#00ff00"  # Green for high

            size = min(20 + attrs['bandwidth'] / 500, 50)

            net.add_node(node, label=node, title=f"{node}: {attrs['bandwidth']} Mbps",
                         color=color, size=size)
        else:
            net.add_node(node, label=node, title=node, color="#6AAFFF", size=20)

    # Add edges
    for edge in G.edges():
        net.add_edge(edge[0], edge[1])

    # Compute network statistics
    valid_bandwidths = [bw for bw in bandwidths.values() if bw > 0]
    if valid_bandwidths:
        total_bandwidth = sum(valid_bandwidths)
        avg_bandwidth = total_bandwidth / len(valid_bandwidths)
        min_bandwidth = min(valid_bandwidths)
        bottleneck_node = [n for n, bw in bandwidths.items() if bw == min_bandwidth][0]
    else:
        total_bandwidth = avg_bandwidth = min_bandwidth = 0
        bottleneck_node = "Unknown"

    # Add network statistics
    stats_html = f"""
    <div style="background-color: #333; color: white; padding: 15px; margin-top: 20px; border-radius: 5px;">
        <h2>Network Statistics</h2>
        <p><strong>Total Measured Bandwidth:</strong> {total_bandwidth:.2f} Mbps</p>
        <p><strong>Average Bandwidth per Hop:</strong> {avg_bandwidth:.2f} Mbps</p>
        <p><strong>Network Bottleneck:</strong> {bottleneck_node} with {min_bandwidth:.2f} Mbps</p>
        <p><strong>End-to-end Effective Bandwidth:</strong> {min_bandwidth:.2f} Mbps</p>
    </div>
    """

    # Save the visualization
    html_file = "network_topology.html"
    html_content = net.generate_html()
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    # Inject stats into the HTML file
    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    modified_html = html_content.replace('</body>', f'{stats_html}</body>')

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(modified_html)

 
if __name__ == "__main__":
    traceroute_file = "traceroute_output.txt"
    traceroute_data = parse_traceroute_file(traceroute_file)
    create_network_visualization(traceroute_data)
    html_file = os.path.abspath("network_topology.html")
    os.system(f"wslview {html_file}")  
    print(f"Network visualization saved to {html_file} and opened in browser")
    


