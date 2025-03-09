import streamlit as st
import frida
import asyncio

def on_message(message, data):
    global output
    if message['type'] == 'send':
        output = message['payload']
    elif message['type'] == 'error':
        print(f"[-] {message['stack']}")

def scanner_main(device):
    st.title("Quick Security Scan")
    try:
        if not device:
            device = frida.get_usb_device()
        installed_apps = device.enumerate_applications()
        app_names = [(app.name, app.identifier) for app in installed_apps]
        selected_app = st.selectbox("Select an app to scan", app_names)
        app = device.enumerate_applications(identifiers=[selected_app[1]], scope="full")[0]
        pid = app.pid if app.pid else device.spawn(app.identifier)
        device.resume(pid)
        session = device.attach(pid)
        device.resume(pid)
        stay_awake_script = open("scripts/stay_awake.js").read()
        stay_awake = session.create_script(stay_awake_script)
        stay_awake.on("message", on_message)
        stay_awake.load()
        asyncio.run(perform_scan(session, app))
        
    except Exception as e:
        st.error(f"Error: {e}")
        
async def run_scan_script(session):
    scanner_script = session.create_script(open("scripts/scanner.js").read())
    scanner_script.on("message", on_message)
    await asyncio.to_thread(scanner_script.load)
    result = await scanner_script.exports_async.scanner()
    scanner_script.unload()
    return result

async def perform_scan(session, app):
    data = await run_scan_script(session)
    info_plist = data['infoPlistJSON']
    result = await check_security_issues(info_plist)
    display_results(result, app)

def display_results(results, app):
    st.subheader("Scan Results")
    
    with st.container(border=True):
        col1, col2 = st.columns([1, 5])
        with col1:
            icon_data = app.parameters.get('icons', [])[0].get('image')
            st.image(icon_data, width=120)
        with col2:
            st.markdown(f"""
                **Name:** {app.name}  
                **Identifier:** {app.identifier}  
                **Pid:** {app.pid}  
                **Version:** {app.parameters['version']}  
                **Path:** {app.parameters['path']}  
            """)
    
    for category, issues in results.items():
        if issues:
            with st.expander(f"{category} ({len(issues)})", expanded=True):
                st.markdown("""
                    <style>
                        .scan-results-table {
                            width: 100%;
                            border-collapse: collapse;
                        }
                        .scan-results-table th, .scan-results-table td {
                            border: 1px solid #ddd;
                            padding: 8px;
                            text-align: left;
                        }
                        .scan-results-table th {
                            background-color: #242424;
                        }
                    </style>
                """, unsafe_allow_html=True)
                
                table_html = "<table class='scan-results-table'><tr><th>Check</th><th>Description</th><th>Severity</th><th>Value</th></tr>"
                for issue in issues:
                    table_html += f"<tr><td>{issue['name']}</td><td>{issue['description']}</td><td>{issue['severity']}</td><td>{issue['value']}</td></tr>"
                table_html += "</table>"
                
                st.markdown(table_html, unsafe_allow_html=True)

async def check_security_issues(plist):
    results = {
        "App Transport Security Issues": [],
        "URL Scheme Issues": [],
        "File Sharing & Data Exposure Issues": [],
        "Permissions Issues": [],
    }

    important_permissions = [
        "NSCameraUsageDescription",
        "NSMicrophoneUsageDescription",
        "NSPhotoLibraryUsageDescription",
        "NSLocationWhenInUseUsageDescription",
        "NSUserTrackingUsageDescription",
    ]
    for key in important_permissions:
        if key in plist:
            results["Permissions Issues"].append({
                "name": key,
                "description": "This permission is present in the Info.plist. Ensure proper justification for its use.",
                "severity": "Medium",
                "value": plist[key]
            })
    
    if plist.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads", False):
        results["App Transport Security Issues"].append({
            "name": "NSAllowsArbitraryLoads",
            "description": "App Transport Security is disabled, which can allow insecure connections.",
            "severity": "High",
            "value": plist["NSAppTransportSecurity"]
        })
    
    if plist.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoadsInWebContent", False):
        results["App Transport Security Issues"].append({
            "name": "NSAllowsArbitraryLoadsInWebContent",
            "description": "This allows arbitrary loads in web content, which can be a security risk.",
            "severity": "Medium",
            "value": plist["NSAppTransportSecurity"]
        })
    
    if "LSApplicationQueriesSchemes" in plist:
        results["URL Scheme Issues"].append({
            "name": "LSApplicationQueriesSchemes",
            "description": "This key allows querying other apps. Ensure no excessive queries.",
            "severity": "Medium",
            "value": plist["LSApplicationQueriesSchemes"]
        })
    
    if "CFBundleURLTypes" in plist:
        results["URL Scheme Issues"].append({
            "name": "CFBundleURLTypes",
            "description": "Custom URL schemes can introduce security risks if not validated properly.",
            "severity": "Medium",
            "value": plist["CFBundleURLTypes"]
        })
    
    if plist.get("UIFileSharingEnabled", False):
        results["File Sharing & Data Exposure Issues"].append({
            "name": "UIFileSharingEnabled",
            "description": "Enabling this allows unauthorized access to app data via iTunes.",
            "severity": "High",
            "value": plist["UIFileSharingEnabled"]
        })
    
    if plist.get("LSSupportsOpeningDocumentsInPlace", False):
        results["File Sharing & Data Exposure Issues"].append({
            "name": "LSSupportsOpeningDocumentsInPlace",
            "description": "This allows opening documents in place, which may expose sensitive data.",
            "severity": "Medium",
            "value": plist["LSSupportsOpeningDocumentsInPlace"]
        })
    
    return results
