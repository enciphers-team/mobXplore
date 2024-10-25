import streamlit as st
import frida

def ipa_manager():
    # st.header("IPA Manager")
    
    st.markdown(
    f"""
    <h1 style='text-align: center;'>IPA Manager (Under Development)</h1>
    
    """,unsafe_allow_html=True)
    try:
        if st.session_state.get('device'):
            device = st.session_state.get('device')
        else:
            device = frida.get_usb_device()
        with st.expander("Extract IPA ", expanded=True):
            installed_apps = device.enumerate_applications()
            app_names = [app.name for app in installed_apps]

            selected_app = st.selectbox("Select an app to extract IPA", app_names)
            if st.button("Extract IPA"):
                extract_ipa(selected_app)

        with st.expander("Sideload IPA",expanded=True):
            uploaded_file = st.file_uploader("Upload an IPA file to sideload", type=["ipa"])
            if uploaded_file and st.button("Sideload IPA"):
                st.write(f"Sideloading IPA: {uploaded_file.name}...")
                st.success(f"IPA {uploaded_file.name} sideloaded successfully.")
    except Exception as e:
        st.error(f"Error: {e}")

def extract_ipa(selected_app):
    st.write(f"Starting the IPA extraction process for: **{selected_app}**")
    # Extraction logic here

