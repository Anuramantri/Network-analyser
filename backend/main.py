from fastapi import FastAPI, Form
from fastapi.responses import FileResponse
import os
from map import parse_traceroute_file, generate_map
from network import build_graph, parse_traceroute
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from network_analysis import load_and_process_data, plot_hop_metrics
import time

app = FastAPI()
IPINFO_TOKEN = "a2b763057ddcfd"

@app.post("/run_traceroute")
async def run_traceroute (
    destination: str = Form(...),
    packet_type: str = Form("icmp")  # either "icmp" or "udp"
):
    output_file = "traceroute_output.txt"
    stats_file = "stats.txt"
    hops_file= 'unexpected_hops.txt'

    # Decide which binary to run based on packet_type
    if packet_type == "udp":
        cmd = f"sudo ./traceroute_udp {destination}"
    else:
        cmd = f"sudo ./traceroute_icmp {destination}"

    result = os.system(cmd)

    if result != 0:
        return {"error": "Traceroute tool failed to run."}

    # Parse and generate fresh outputs
    traceroute_data = parse_traceroute_file(output_file)
    generate_map(traceroute_data, IPINFO_TOKEN)

    traceroute_data2,destination = parse_traceroute(output_file)
    build_graph(traceroute_data2,dest_ip=destination)

    if os.path.exists("traceroute_map.html"):
        os.utime("traceroute_map.html", None)
    if os.path.exists("network_topology.html"):
        os.utime("network_topology.html", None)

    with open(output_file, "r") as f:
        traceroute_text = f.read()

    with open(stats_file, "r") as f:
        stats = f.read()

    with open(hops_file, "r") as f:
        hops = f.read().strip()

    response = {
        "message": "Traceroute completed",
        "map_url": "/map",
        "network_topology_url": "/network_topology",
        "traceroute_output": traceroute_text,
        "stats": stats,
    }

    if hops:
        response["unexpected_hops"] = hops

    return response


@app.get("/map")
async def get_map():
    if not os.path.exists("traceroute_map.html"):
        return JSONResponse(
            content={"error": "Map not generated."},
            status_code=404
        )
    return FileResponse("traceroute_map.html", media_type="text/html")

@app.get("/network_topology")
async def get_topology():
    if not os.path.exists("network_topology.html"):
        return JSONResponse(
            content={"error": "Topology not generated."},
            status_code=404
        )
    return FileResponse("network_topology.html")

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