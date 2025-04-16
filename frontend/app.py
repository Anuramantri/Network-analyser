import streamlit as st
import requests
import streamlit.components.v1 as components
import io
from PIL import Image
import time

st.title("Bandwit: Network Analysis and Bandwidth Visualizer")

# Initialize session state
if "traceroute_ran" not in st.session_state:
    st.session_state.traceroute_ran = False
if "traceroute_data" not in st.session_state:
    st.session_state.traceroute_data = None
if "show_plots" not in st.session_state:
    st.session_state.show_plots = False

# User inputs
destination = st.text_input("Enter destination address or domain name")
packet_type = st.radio("Select Packet Type", ("ICMP", "UDP"))

# Run button
if st.button("Run"):
    if not destination:
        st.warning("Please enter a destination.")
    else:
        with st.spinner("Running tool..."):
            response = requests.post(
                "http://localhost:8000/run_traceroute",
                data={"destination": destination, "packet_type": packet_type.lower()}
            )

            if response.ok:
                st.session_state.traceroute_ran = True
                st.session_state.traceroute_data = response.json()
                st.session_state.show_plots = False  # Reset plot state
                st.success("Traceroute completed!")
            else:
                st.error("Traceroute failed to run.")
                st.session_state.traceroute_ran = False

timestamp = int(time.time())
map_url = f"http://localhost:8000/map?v={timestamp}"
topo_url = f"http://localhost:8000/network_topology?v={timestamp}"

# Display results if traceroute ran successfully
if st.session_state.traceroute_ran and st.session_state.traceroute_data:
    data = st.session_state.traceroute_data

    st.markdown("### Network Path Map")
    map_response = requests.get(map_url)

    if map_response.ok:
        components.html(map_response.text, height=500, width=700)
    else:
        st.warning("⚠️ Map not generated")


    st.markdown("### Network Topology")
    topo_response = requests.get(topo_url)

    if topo_response.ok:
        components.html(topo_response.text, height=500, width=700)
    else:
        st.warning("⚠️ Topology not generated")

    st.markdown("### Raw Output")
    st.code(data["traceroute_output"], language="text")

    st.markdown("### Network Statistics")
    st.code(data["stats"], language="text")

    if "unexpected_hops" in data:
        st.subheader("Unexpected Hops Detected")
        st.code(data["unexpected_hops"])

    # Time of Day selector and plot trigger
    st.markdown("### Visual Output (Plots)")
    time_of_day = st.selectbox("Select Time of Day", ["Morning", "Afternoon", "Evening", "Night"])

    if st.button("Show RTT & Bandwidth Plots"):
        st.session_state.show_plots = True

    # Show plots if requested
    if st.session_state.show_plots:
        with st.spinner("Loading plots..."):
            plot_response = requests.get(
                "http://localhost:8000/plots",
                params={
                    "time_of_day": time_of_day,
                    "protocol": packet_type,
                    "destination": destination
                }
            )

            if plot_response.ok:
                plot_data = plot_response.json()

                # Fetch RTT image
                rtt_url = f"http://localhost:8000{plot_data['rtt_plot']}"
                rtt_img_response = requests.get(rtt_url)

                # Fetch Bandwidth image
                bw_url = f"http://localhost:8000{plot_data['bandwidth_plot']}"
                bw_img_response = requests.get(bw_url)

                if rtt_img_response.ok and bw_img_response.ok:
                    rtt_img = Image.open(io.BytesIO(rtt_img_response.content))
                    bw_img = Image.open(io.BytesIO(bw_img_response.content))

                    st.subheader("RTT per Hop")
                    st.image(rtt_img, caption="RTT Plot")

                    st.subheader("Bandwidth per Hop")
                    st.image(bw_img, caption="Bandwidth Plot")
                else:
                    st.error("Failed to fetch one or both plot images.")
            else:
                st.error("Failed to load plots.")
else:
    st.info("Run a traceroute to generate the latest map and network topology.")

