# Bandwit: Network Analysis and Bandwidth Visualizer

This is our course project for CS331 Computer Networks.

Bandwit is a course project for CS331: Computer Networks, designed to provide an in-depth visualization of network paths and bandwidth metrics.
This tool performs hop-by-hop tracerouting while estimating bandwidth, RTT (Round-Trip Time), and jitter at each hop.
It provides a visualization of network topology and plots the IPs on a geographical map.

Run the project on WSL (Windows Subsystem for Linux) or a Linux system.
Clone the repo and follow the given instructions to run. 

You may need to install tools listed in requirements.txt
To install run:
```
pip install -r requirements.txt
```

### To run frontend:

```
cd frontend
streamlit run app.py 
```


### To run backend:

```
cd backend
uvicorn main:app --reload
```
You will be prompted for your sudo password to run low-level network tools. 




