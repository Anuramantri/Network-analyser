from fastapi import FastAPI, Form
from fastapi.responses import FileResponse
import subprocess
import os
from traceroute_map import parse_traceroute_file, generate_map

app = FastAPI()

@app.post("/run_traceroute")
async def run_traceroute(destination: str = Form(...)):
    output_file = "traceroute_output.txt"
    stats_file = "stats.txt"

    cmd = f"sudo ./mytool {destination} > {output_file}"
    result = subprocess.run(cmd, shell=True)

    if result.returncode != 0:
        return {"error": "Traceroute tool failed to run."}
    
    traceroute_data = parse_traceroute_file(output_file)
    generate_map(traceroute_data)
    
    
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

