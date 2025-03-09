import streamlit as st
import asyncio
# Import functions from the 'functions' folder
from functions import home, device_info, app_manager, ipa_manager, remote_device, quick_scan
from functions.app_explorer import explore_app
from PIL import Image
favicon = Image.open("logo.png")
st.set_page_config(page_title="MobXplore",layout="wide",page_icon=favicon)
st.markdown(
    """
    <style>
    [data-testid="stExpander"] p {
        font-size: 17px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    """
    <style>
        section[data-testid="stSidebar"] {
            width: 300px !important; # Set the width to your desired value
        }
    </style>
    """,
    unsafe_allow_html=True,
)

rmt_device = None
# Custom CSS to make buttons full-width
st.markdown("""
    <style>
    .stButton > button {
        width: 100%;
        margin: 5px 0;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state for page navigation
if 'current_page' not in st.session_state:
    st.session_state['current_page'] = 'home'  # Default page

def navigate_to(page):
    st.session_state['current_page'] = page

def navigation():
    st.sidebar.image('logo.png',caption="By The Creators Of Mobexler")
    # st.sidebar.title("GiPT Navigation")

    # Define buttons for each page, set the state for each page when clicked
    if not remote_device.usb_device_connected():
        if st.sidebar.button("Connect Remote Device"):
            global rmt_device
            st.session_state['device'] = remote_device.connect_remote_device()
    if st.sidebar.button("Home"):
        navigate_to('home')
    if st.sidebar.button("Device Info"):
        navigate_to('device_info')
    if st.sidebar.button("App Explorer"):
        navigate_to('app_manager')
    if st.sidebar.button("IPA Extractor"):
        navigate_to('ipa_manager')
    if st.sidebar.button("Quick Security Scan"):
        navigate_to('security_scan')

    # Check session state for current page
    if st.session_state['current_page'] == 'home':
        home.home_page()
    elif st.session_state['current_page'] == 'device_info':
        device_info.get_device_info()
    elif st.session_state['current_page'] == 'app_manager':
        app_manager.list_installed_apps()
    elif st.session_state['current_page'] == 'ipa_manager':
        ipa_manager.ipa_manager()
    elif st.session_state['current_page'] == 'explore_app':
        asyncio.run(explore_app(st.session_state.get('app_identifier', None), st.session_state.get('device')))
    elif st.session_state['current_page'] == 'security_scan':
        quick_scan.scanner_main(st.session_state.get('device'))
    else:
        # Default to home page if session state is corrupted
        home.home_page()

# Main Entry
if __name__ == "__main__":
    navigation()
