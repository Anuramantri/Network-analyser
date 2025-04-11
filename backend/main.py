from fastapi import FastAPI, Form
from fastapi.responses import FileResponse
import subprocess
import os
from map import parse_traceroute_file, generate_map
from network import create_network_visualization, parse_traceroute

app = FastAPI()
IPINFO_TOKEN = "a2b763057ddcfd"

@app.post("/run_traceroute")
async def run_traceroute(
    destination: str = Form(...),
    packet_type: str = Form("icmp")  # either "icmp" or "udp"
):
    output_file = "traceroute_output.txt"
    stats_file = "stats.txt"

    # Decide which binary to run based on packet_type
    if packet_type == "udp":
        cmd = f"sudo ./udp_tool {destination} > {output_file}"
    else:  # default to icmp
        cmd = f"sudo ./icmp_tool {destination} > {output_file}"

    result = subprocess.run(cmd, shell=True)

    if result.returncode != 0:
        return {"error": "Traceroute tool failed to run."}

    # Process traceroute and generate map
    traceroute_data = parse_traceroute_file(output_file)
    generate_map(traceroute_data,IPINFO_TOKEN)

    traceroute_data2 = parse_traceroute(output_file)
    create_network_visualization(traceroute_data2)

    # Read raw output and stats
    with open(output_file, "r") as f:
        traceroute_text = f.read()

    with open(stats_file, "r") as f:
        stats = f.read()

    return {
        "message": "Traceroute completed",
        "map_url": "/map",
        "traceroute_output": traceroute_text,
        "stats": stats
    }

@app.get("/map")
async def get_map():
    return FileResponse("traceroute_map.html", media_type="text/html")

@app.get("/network_topology")
async def get_topology():
    return FileResponse("network_topology.html")

