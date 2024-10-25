import streamlit as st
import frida
import base64


def list_installed_apps():
    # st.header("App Explorer")
    # st.subheader("Installed Applications")
    st.markdown(
    f"""
    <h1 style='text-align: center;'>App Explorer</h1>
    
    """,unsafe_allow_html=True)
    try:
        if st.session_state.get('device'):
            device = st.session_state.get('device')
        else:
            device = frida.get_usb_device()
        
        apps = device.enumerate_applications(scope="full")

        search_query = st.text_input("Search for an app", "")
        filtered_apps = [app for app in apps if search_query.lower() in app.name.lower()]

        if filtered_apps:
            num_cols = 3
            num_rows = (len(filtered_apps) + num_cols - 1) // num_cols
            for row in range(num_rows):
                columns = st.columns(num_cols)
                for col in range(num_cols):
                    index = row * num_cols + col
                    if index < len(filtered_apps):
                        app = filtered_apps[index]
                        with columns[col]:
                            with st.form(key=f"explore_form_{app.identifier}"):
                                app_details = f"""
                                <div style='border: 0px solid #ccc; padding: 0px; border-radius: 8px; width: 100%;'>
                                    <div style='display: flex; align-items: center;'>
                                        <div style='margin-right: 10px;'>
                                            <img src='data:image/png;base64,{get_app_icon_base64(app)}' width='100'/>
                                        </div>
                                        <div>
                                            <strong>Version:</strong> {app.parameters.get('version', 'Unknown')}<br>
                                            <strong>Build:</strong> {app.parameters.get('build', 'Unknown')}<br>
                                            <strong>Bundle ID:</strong> {app.identifier}<br>
                                            <strong>PID:</strong> {app.pid if app.pid else 'Not Running'}<br>
                                        </div>
                                    </div>
                                </div>
                                """
                                st.markdown(app_details, unsafe_allow_html=True)
                                submitted = st.form_submit_button(f"Explore {app.name}")
                                if submitted:
                                    st.session_state['current_page'] = 'explore_app'
                                    st.session_state['app_identifier'] = app.identifier
                                    st.session_state['device'] = device
                                    st.rerun()
        else:
            st.write("No apps found matching the search query.")
    except Exception as e:
        st.error(f"Error: {e}")

def get_app_icon_base64(app):
    try:
        icon_data = app.parameters.get('icons', [])[0].get('image')
        if icon_data:
            return base64.b64encode(icon_data).decode('utf-8')
    except (IndexError, KeyError, TypeError):
        pass
    return ""

