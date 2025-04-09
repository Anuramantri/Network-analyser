import folium
import requests
import os
import re
from folium.plugins import AntPath

def parse_traceroute_file(filename):
    """
    Reads traceroute output and extracts hop details.
    Returns:
        List of tuples (hop, ip_address, rtt, bandwidth)
    """
    traceroute_data = []
    with open(filename, 'r') as file:
        lines = file.readlines()

    parsing = False
    for line in lines:
        if "Hop\tIP Address" in line:
            parsing = True
            continue
        if "--- Network Statistics ---" in line:
            break
        
        if parsing:
            match = re.match(r"(\d+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)", line)
            if match:
                hop = int(match.group(1))
                ip_address = match.group(2)
                rtt = float(match.group(3))
                bandwidth = float(match.group(4))
                traceroute_data.append((hop, ip_address, rtt, bandwidth))

    return traceroute_data

def get_ip_location(ip):
    """Fetches geolocation of public IPs using ipinfo.io"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        if "loc" in response:
            lat, lon = map(float, response["loc"].split(","))
            return lat, lon
    except:
        pass
    return None

def generate_map(traceroute_data):
    """Generates an interactive map with traceroute hops."""
    
    map_center = (20, 0)  # Default center
    folium_map = folium.Map(location=map_center, zoom_start=3)
    
    locations = []
    for hop, ip, rtt, bandwidth in traceroute_data:
        location = get_ip_location(ip)
        if location:
            locations.append((ip, location, rtt, bandwidth))

    for i in range(len(locations) - 1):
        popup_html = f"""
        <div style="font-family: Arial; font-size: 12px; color: black; padding: 5px; width: 200px;">
            <strong>IP Address:</strong> {locations[i][0]}<br>
            <strong>RTT:</strong> {locations[i][2]} ms<br>
            <strong>Bandwidth:</strong> {locations[i][3]} Mbps
        </div>
        """
        folium.Marker(
            locations[i][1],
            popup=folium.Popup(popup_html, max_width=300),
            icon=folium.Icon(color='blue', icon='info-sign')
        ).add_to(folium_map)
        AntPath([locations[i][1], locations[i + 1][1]], color="red").add_to(folium_map)


# Last hop marker
    popup_html = f"""
    <div style="font-family: Arial; font-size: 12px; color: black; padding: 5px; width: 200px;">
        <strong>IP Address:</strong> {locations[-1][0]}<br>
        <strong>RTT:</strong> {locations[-1][2]} ms<br>
        <strong>Bandwidth:</strong> {locations[-1][3]} Mbps
    </div>
    """
    folium.Marker(
        locations[-1][1],
        popup=folium.Popup(popup_html, max_width=300),
        icon=folium.Icon(color='red', icon='info-sign')  # Different color for the last hop
    ).add_to(folium_map)


    # Save map
    folium_map.save("traceroute_map.html")



if __name__ == "__main__":
    traceroute_file = "traceroute_output.txt"
    traceroute_data = parse_traceroute_file(traceroute_file)
    generate_map(traceroute_data)
    os.system("wslview stats.html" if os.name == "posix" else "start stats.html")
