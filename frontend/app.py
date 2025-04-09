import streamlit as st
import requests
import streamlit.components.v1 as components

st.title("Network Analysis and Bandwidth Visualizer")

destination = st.text_input("Enter destination address or domain name")

if st.button("Run"):
    with st.spinner("Running tool..."):
        response = requests.post("http://localhost:8000/run_traceroute", data={"destination": destination})
        if response.ok:
            data = response.json()
            st.success("Completed!")

            # Show map
            st.markdown("### Network Path Map")
            components.iframe("http://localhost:8000/map", height=500, width=700)

            # Show traceroute text
            st.markdown("### Raw Output")
            st.code(data["traceroute_output"], language="text")

            st.markdown("### Network Statistics")
            st.code(data["stats"], language="text")


        else:
            st.error("Traceroute failed to run.")
