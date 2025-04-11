import streamlit as st
import requests
import streamlit.components.v1 as components

st.title("Network Analysis and Bandwidth Visualizer")

destination = st.text_input("Enter destination address or domain name")

# Packet type selection
packet_type = st.radio("Select Packet Type", ("ICMP", "UDP"))

if st.button("Run"):
    with st.spinner("Running tool..."):
        response = requests.post(
            "http://localhost:8000/run_traceroute",
            data={"destination": destination, "packet_type": packet_type.lower()}
        )

        if response.ok:
            data = response.json()
            st.success("Completed!")

            st.markdown("### Network Path Map")
            components.iframe("http://localhost:8000/map", height=500, width=700)

            st.markdown("### Network Topology")
            components.iframe("http://localhost:8000/network_topology", height=750, width=900)

            st.markdown("### Raw Output")
            st.code(data["traceroute_output"], language="text")

            # Show stats
            st.markdown("### Network Statistics")
            st.code(data["stats"], language="text")

        else:
            st.error("Traceroute failed to run.")

# response = requests.post(
#             "http://localhost:8000/run_traceroute",
#             data={"destination": destination, "packet_type": packet_type.lower()}
#         )
# plot_names = [ "bandwidth_afternoon"]

# st.markdown("### Visual Output (Plots)")

# for name in plot_names:
#     image_url = f"http://localhost:8000/plot/{name}"
#     st.image(image_url, caption=name, use_column_width=True)
