from fastapi import FastAPI, Form
from fastapi.responses import FileResponse
import subprocess
import os
from map import parse_traceroute_file, generate_map
from network import create_network_visualization, parse_traceroute
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from network_analysis import load_and_process_data, plot_hop_metrics


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
        cmd = f"sudo ./traceroute_udp {destination} > {output_file}"
    else:  # default to icmp
        cmd = f"sudo ./traceroute_icmp {destination} > {output_file}"

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
        "network_topology_url": "/network_topology",
        "traceroute_output": traceroute_text,
        "stats": stats
    }

@app.get("/map")
async def get_map():
    return FileResponse("traceroute_map.html", media_type="text/html")

@app.get("/network_topology")
async def get_topology():
    return FileResponse("network_topology.html")

# @app.get("/plots")
# async def get_plots(time_of_day: str = "Morning", protocol: str = "ICMP"):
#     protocol = protocol.upper()
#     if protocol not in ["ICMP", "UDP"]:
#         return JSONResponse(content={"error": "Unsupported protocol"}, status_code=400)

#     csv_file = "traceroute_icmp.csv" if protocol == "ICMP" else "traceroute_udp.csv"
#     df = load_and_process_data(csv_file)
    
#     if df is None:
#         return JSONResponse(content={"error": "No data available"}, status_code=404)

#     plot_hop_metrics(df, time_of_day, out_dir="static")

#     return {
#         "rtt_plot": f"/static/rtt_{time_of_day.lower()}.png",
#         "bandwidth_plot": f"/static/bandwidth_{time_of_day.lower()}.png"
# }
@app.get("/plots")

async def get_plots(
    time_of_day: str = "Morning",
    protocol: str = "ICMP",
    destination: str = ""
):

    protocol = protocol.upper()
    if protocol not in ["ICMP", "UDP"]:
        return JSONResponse(content={"error": "Unsupported protocol"}, status_code=400)

    csv_file = "traceroute_icmp.csv" if protocol == "ICMP" else "traceroute_udp.csv"
    
    # Now passing destination as target_ip
    df = load_and_process_data(csv_file, target_ip=destination)
    app.mount("/static", StaticFiles(directory="static"), name="static")
    if df is None:
        return JSONResponse(content={"error": f"No data available for IP {destination}"}, status_code=404)

    plot_hop_metrics(df, time_of_day, target_ip=destination, out_dir="static",protocol=protocol)

    ip_safe = destination.replace(".", "_") if destination else "unknown"

    return {
        "rtt_plot": f"/static/rtt_{time_of_day.lower()}_{ip_safe}_{protocol}.png",
        "bandwidth_plot": f"/static/bandwidth_{time_of_day.lower()}_{ip_safe}_{protocol}.png"
}