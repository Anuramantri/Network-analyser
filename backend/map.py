import folium
import requests
import re
from folium.plugins import AntPath
from ipaddress import ip_address

IPINFO_TOKEN = "a2b763057ddcfd" # unlimited api requests with this token

def is_public_ip(ip):
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False

def parse_traceroute_file(file_path):
    unique_ips = []
    seen = set()

    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(r"Probe\s+\d+:\s+([\d\.]+)", line)
            if match:
                ip = match.group(1)
                if is_public_ip(ip) and ip not in seen:
                    seen.add(ip)
                    unique_ips.append(ip)

    return unique_ips



def get_ip_location(ip, token):
    """Fetches geolocation of public IPs using ipinfo.io with token"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}", timeout=3)
        data = response.json()
        if "loc" in data:
            lat, lon = map(float, data["loc"].split(","))
            return lat, lon
    except Exception as e:
        print(f"[!] Failed to fetch location for {ip}: {e}")
    return None


def generate_map(traceroute_data, token):
    """Generates an interactive map with traceroute hops."""
    
    map_center = (20, 0)  # Default center
    folium_map = folium.Map(location=map_center, zoom_start=3)
    
    locations = []
    for ip in traceroute_data:
        location = get_ip_location(ip, token)
        if location:
            locations.append((ip, location))

    for i in range(len(locations) - 1):
        popup_html = f"""
        <div style="font-family: Arial; font-size: 12px; color: black; padding: 5px; width: 200px;">
            <strong>IP Address:</strong> {locations[i][0]}<br>
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
    </div>
    """
    folium.Marker(
        locations[-1][1],
        popup=folium.Popup(popup_html, max_width=300),
        icon=folium.Icon(color='red', icon='info-sign')
    ).add_to(folium_map)

    # Save map
    folium_map.save("traceroute_map.html")
    print("[+] Map saved as traceroute_map.html")
