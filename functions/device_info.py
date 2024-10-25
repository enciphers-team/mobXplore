import streamlit as st
import subprocess
import pandas as pd

def get_device_info():
    st.markdown(
    f"""
    <h1 style='text-align: center;'>Device Information</h1>
    
    """,unsafe_allow_html=True)
    # st.header("Device Information")
    try:
        result = subprocess.run(["ideviceinfo"], capture_output=True, text=True)
        if result.returncode == 0:
            data = []
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':', 1)
                    property_name = parts[0].strip()
                    value = parts[1].strip()
                    data.append([property_name, value])

            df = pd.DataFrame(data, columns=["Property", "Value"])
            st.table(df)
        else:
            st.error("Could not retrieve device information.")
    except Exception as e:
        st.error(f"Error: {e}")

