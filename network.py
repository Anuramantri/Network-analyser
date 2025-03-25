import networkx as nx
from pyvis.network import Network
import os
import webbrowser
from IPython.display import IFrame, display, HTML

def create_network_visualization(traceroute_data=None):
    """
    Create and display a network visualization of traceroute data
    
    Parameters:
    traceroute_data: List of tuples (hop, ip_address, rtt, bandwidth)
                     If None, uses example data
    """
    # Create a directed graph
    G = nx.DiGraph()
    
    # Use example data if none provided
    if traceroute_data is None:
        # Example data from the traceroute output
        nodes = [
            "Source", "172.26.192.1", "10.7.0.5", "172.16.4.4", "14.139.98.1",
            "10.117.81.253", "10.154.8.137", "10.255.239.170", "10.152.7.214",
            "72.14.238.215", "192.178.110.104", "108.170.225.191", "142.251.250.172",
            "142.251.250.50", "142.250.213.61", "216.239.58.255", "172.253.72.146",
            "216.239.59.76", "192.178.98.7", "108.170.234.221", "142.250.200.14"
        ]
        
        bandwidths = {
            "172.26.192.1": 110.32,
            "10.117.81.253": 3.08,
            "10.154.8.137": 2.90,
            "10.255.239.170": 24.36,
            "72.14.238.215": 19.49,
            "192.178.110.104": 5.31,
            "142.251.250.50": 0.19,
            "142.250.213.61": 0.54,
            "172.253.72.146": 0.97,
            "192.178.98.7": 0.34,
            "108.170.234.221": 0.49
        }
    else:
        # Process the provided traceroute data
        nodes = ["Source"]
        bandwidths = {}
        
        for hop, ip, rtt, bw in traceroute_data:
            nodes.append(ip)
            if bw > 0:
                bandwidths[ip] = bw
    
    # Add nodes to the graph with bandwidth as attribute
    for node in nodes:
        if node in bandwidths:
            G.add_node(node, bandwidth=bandwidths[node], title=f"{node}: {bandwidths[node]} Mbps")
        else:
            G.add_node(node, title=node)
    
    # Add edges representing the path
    for i in range(len(nodes)-1):
        G.add_edge(nodes[i], nodes[i+1])
    
    # Create interactive visualization
    # Use in_line for cdn_resources to ensure it works offline
    net = Network(notebook=False, cdn_resources="in_line", 
                  bgcolor="#222222", font_color="white",
                  height="750px", width="100%")
    
    # Set options for better visualization
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
    
    # Add nodes with colors based on bandwidth
    for node, attrs in G.nodes(data=True):
        if 'bandwidth' in attrs:
            # Use color scale: red for low bandwidth, green for high
            if attrs['bandwidth'] < 5:  # Bottleneck threshold
                color = "#ff0000"  # Red for bottlenecks
            elif attrs['bandwidth'] < 20:
                color = "#ffaa00"  # Orange for medium bandwidth
            else:
                color = "#00ff00"  # Green for high bandwidth
            
            # Size nodes based on bandwidth (min 20, max 50)
            size = min(20 + attrs['bandwidth']/3, 50)
            
            net.add_node(node, label=node, title=f"{node}: {attrs['bandwidth']} Mbps", 
                        color=color, size=size)
        else:
            # Default size and color for nodes without bandwidth info
            net.add_node(node, label=node, title=node, color="#6AAFFF", size=20)
    
    # Add edges
    for edge in G.edges():
        net.add_edge(edge[0], edge[1])
    
    # Calculate network statistics
    valid_bandwidths = [bw for bw in bandwidths.values() if bw > 0]
    if valid_bandwidths:
        total_bandwidth = sum(valid_bandwidths)
        avg_bandwidth = total_bandwidth / len(valid_bandwidths)
        min_bandwidth = min(valid_bandwidths)
        bottleneck_node = [n for n, bw in bandwidths.items() if bw == min_bandwidth][0]
    else:
        total_bandwidth = avg_bandwidth = min_bandwidth = 0
        bottleneck_node = "Unknown"
    
    # Add network statistics to the visualization
    stats_html = f"""
    <div style="background-color: #333; color: white; padding: 15px; margin-top: 20px; border-radius: 5px;">
        <h2>Network Statistics</h2>
        <p><strong>Total Measured Bandwidth:</strong> {total_bandwidth:.2f} Mbps</p>
        <p><strong>Average Bandwidth per Hop:</strong> {avg_bandwidth:.2f} Mbps</p>
        <p><strong>Network Bottleneck:</strong> {bottleneck_node} with {min_bandwidth:.2f} Mbps</p>
        <p><strong>End-to-end Effective Bandwidth:</strong> {min_bandwidth:.2f} Mbps</p>
    </div>
    """
    
    # Generate HTML file with network statistics - FIX: Use UTF-8 encoding
    html_file = "network_topology.html"
    
    # Instead of using save_graph which has encoding issues
    html_content = net.generate_html()
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Add network statistics to the HTML file
    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Insert stats before the closing body tag
    modified_html = html_content.replace('</body>', f'{stats_html}</body>')
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(modified_html)
    
    # Open the HTML file in the default browser
    webbrowser.open('file://' + os.path.realpath(html_file), new=2)
    
    # For Jupyter Notebook, also display inline
    try:
        # Check if running in Jupyter
        get_ipython
        # Display the visualization in the notebook
        display(HTML(modified_html))
    except:
        print(f"Network visualization saved to {html_file} and opened in browser")
        print(f"Total Bandwidth: {total_bandwidth:.2f} Mbps")
        print(f"Bottleneck: {bottleneck_node} with {min_bandwidth:.2f} Mbps")

if __name__ == "__main__":
    create_network_visualization()
