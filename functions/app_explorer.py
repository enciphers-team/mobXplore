import asyncio
import frida
import base64
import sys
import pandas as pd
import json, io
from streamlit_ace import st_ace
from functions.app_manager import *

output = None
script_loader_output = []

def on_message(message, data):
    global output
    if message['type'] == 'send':
        output = message['payload']
    elif message['type'] == 'error':
        print(f"[-] {message['stack']}")

# Async function to create a session and load the stay awake script
async def get_session(app_identifier, device):
    app = device.enumerate_applications(identifiers=[app_identifier],scope="full")[0]
    pid = app.pid if app.pid else await asyncio.to_thread(device.spawn, app_identifier)

    session = await asyncio.to_thread(device.attach, pid)

    # Load stay_awake script asynchronously
    stay_awake_script = open("scripts/stay_awake.js").read()
    stay_awake = session.create_script(stay_awake_script)
    stay_awake.on("message", on_message)
    await asyncio.to_thread(stay_awake.load)
    
    await asyncio.to_thread(device.resume, pid)
    return session, app, pid

# Async function to fetch basic app info
async def get_info_plist_async(session):
    script = session.create_script(open("scripts/info_async.js").read())
    script.on("message", on_message)
    await asyncio.to_thread(script.load)

    # Call Frida's async export
    result = await script.exports_async.get_info_plist()
    script.unload()
    return result

# Async function to display basic app information
async def basic_info(app, session, pid, device):
    global output
    with st.container(border=True, height=170):
        col1, col2 = st.columns([1, 5])

        with col1:
            icon_data = app.parameters.get('icons', [])[0].get('image')
            st.image(icon_data, width=120)

        with col2:
            st.markdown(f"""
            **Name**: {app.name}  
            **Identifier**: {app.identifier}  
            **Pid**: {app.pid}  
            **Version**: {app.parameters['version']}  
            **Path**: {app.parameters['path']}
            """)
    with st.container(border=True, height=650):
        # Fetch Info.plist details asynchronously
        info_plist = await get_info_plist_async(session)

        # Update UI with fetched information
        st.markdown(f"**Bundle Path**: `{info_plist['bundlePath']}`")
        st.markdown(f"**Info.plist Path**: `{info_plist['infoPlistPath']}`")
        st.markdown("**Info.plist Content**:")
        st.code(info_plist['infoPlistContent'], language='json')

# Async function to load and execute Frida script from editor
async def run_script_loader(app, session, pid, device):
    global script_loader_output

    def script_loader_on_message(message, data):
        global script_loader_output
        if message['type'] == 'send':
            script_loader_output.append(message['payload'])
        elif message['type'] == 'error':
            script_loader_output.append(message['stack'])

    col1, col2 = st.columns(2, gap='small')
    code = ""
    with col1:
        st.markdown(" ###### Script Editor:")
        with st.container(height=800):
            code = st_ace(language="javascript", theme="nord_dark", placeholder="// Frida Script Goes Here !!", height=700)
            code = code.replace("console.log", "send")

    with col2:
        st.markdown(" ###### Output:")
        with st.container(height=800):
            if code:
                script_loader_output.clear()
                tmp_script = session.create_script(code)
                tmp_script.on("message", script_loader_on_message)
                await asyncio.to_thread(tmp_script.load)
                await asyncio.to_thread(device.resume, pid)
                await asyncio.sleep(3)
                st.code(' '.join(script_loader_output), language='javascript')
                tmp_script.unload()

# Async function for storage-related tasks
async def storage_func(app, session, pid, device):
    global output
    with st.expander("**Cookies**", expanded=True):
        cookies_script = session.create_script(open("scripts/cookies.js").read())
        cookies_script.on("message", on_message)
        await asyncio.to_thread(cookies_script.load)
        await asyncio.to_thread(device.resume, pid)
        await asyncio.sleep(2)
        df = pd.read_json(io.StringIO(json.dumps(output))) if output else pd.DataFrame()
        st.dataframe(df,use_container_width=True)
        cookies_script.unload()
        output = None

    with st.expander("**KeyChain Info**", expanded=True):
        keychain_script = session.create_script(open("scripts/keychain.js").read())
        keychain_script.on("message", on_message)
        await asyncio.to_thread(keychain_script.load)
        await asyncio.to_thread(device.resume, pid)
        await asyncio.sleep(2)
        df = pd.read_json(io.StringIO(json.dumps(output))) if output else pd.DataFrame()
        st.dataframe(df,use_container_width=True)
        keychain_script.unload()
        output = None

    with st.expander("**NSUserDefaults**", expanded=True):
        nsuserdefaults_script = session.create_script(open("scripts/nsuserdefaults.js").read())
        nsuserdefaults_script.on("message", on_message)
        await asyncio.to_thread(nsuserdefaults_script.load)
        await asyncio.to_thread(device.resume, pid)
        await asyncio.sleep(2)
        df = pd.read_json(io.StringIO(json.dumps(output))) if output else pd.DataFrame()
        st.dataframe(df,use_container_width=True)
        nsuserdefaults_script.unload()
        output = None

async def get_classes(app, session, pid, device):
	
	with st.container(height=900):
		class_names_script = session.create_script(open("scripts/get_classes.js").read())
		class_names_script.on("message", on_message)
		await asyncio.to_thread(class_names_script.load)
		class_names = await class_names_script.exports_async.get_app_classes()
		class_names_script.unload()
		app_classes = sum([v for k,v in class_names.items() if app.parameters['path'] in k], [])
		selected_class = st.selectbox(f"Select a module to analyse ({len(app_classes)} classes found):", options=app_classes, index=None)

		if selected_class:
			class_detail_script = session.create_script(open("scripts/class_detail.js").read())
			class_detail_script.on("message", on_message)
			await asyncio.to_thread(class_detail_script.load)
			class_detail = await class_detail_script.exports_async.get_class_details(selected_class)
			class_detail_script.unload()
			st.write(class_detail)
			# with st.container(height=85):
			# 	col1,col2,col3 = st.columns(3)
			# 	with col1:
			# 		st.code(f"Module Name: {module_detail['name']}")
			# 	with col2:
			# 		st.code(f"Base Address: {module_detail['base']}")
			# 	with col3:
			# 		st.code(f"Module Size: {module_detail['size']}")
			# imports, exports, symbols = st.tabs(["Imports", "Exports", "Symbols"])
			# with imports:
			# 	for key in module_detail['importsByModule'].keys():
			# 		with st.expander(f"{key}", expanded=False):
			# 			st.write(module_detail['importsByModule'][key])
			# with exports:
			# 	df = pd.read_json(io.StringIO(json.dumps(module_detail['exports']))) if module_detail['exports'] else pd.DataFrame()
			# 	st.dataframe(df,use_container_width=True, height=600)
			# 	# st.write(module_detail['exports'])
			# with symbols:
			# 	df = pd.read_json(io.StringIO(json.dumps(module_detail['symbols']))) if module_detail['symbols'] else pd.DataFrame()
			# 	st.dataframe(df,use_container_width=True, height=600)
			# 	# st.write(module_detail['symbols'])

async def get_modules(app, session, pid, device):

	with st.container(height=900):
		module_names_script = session.create_script(open("scripts/get_modules.js").read())
		module_names_script.on("message", on_message)
		await asyncio.to_thread(module_names_script.load)
		module_names = await module_names_script.exports_async.get_modules()
		module_names_script.unload()
		selected_module = st.selectbox(f"Select a module to analyse ({len(module_names)} modules found):", options=module_names, index=None)

		if selected_module:
			module_detail_script = session.create_script(open("scripts/module_detail.js").read())
			module_detail_script.on("message", on_message)
			await asyncio.to_thread(module_detail_script.load)
			module_detail = await module_detail_script.exports_async.get_module_details(selected_module)
			module_detail_script.unload()
			with st.container(height=85):
				col1,col2,col3 = st.columns(3)
				with col1:
					st.code(f"Module Name: {module_detail['name']}")
				with col2:
					st.code(f"Base Address: {module_detail['base']}")
				with col3:
					st.code(f"Module Size: {module_detail['size']}")
			imports, exports, symbols = st.tabs(["Imports", "Exports", "Symbols"])
			with imports:
				for key in module_detail['importsByModule'].keys():
					with st.expander(f"{key}", expanded=False):
						st.write(module_detail['importsByModule'][key])
			with exports:
				df = pd.read_json(io.StringIO(json.dumps(module_detail['exports']))) if module_detail['exports'] else pd.DataFrame()
				st.dataframe(df,use_container_width=True, height=600)
				# st.write(module_detail['exports'])
			with symbols:
				df = pd.read_json(io.StringIO(json.dumps(module_detail['symbols']))) if module_detail['symbols'] else pd.DataFrame()
				st.dataframe(df,use_container_width=True, height=600)
				# st.write(module_detail['symbols'])


	
# Main function to handle app exploration
async def explore_app(app_identifier, device):
    session, app, pid = await get_session(app_identifier, device)

    # Create tabs and run their respective functions concurrently
    basic, storage_comp, script_loader, modules, classes = st.tabs(["Basic Info", "Storage", "Script Loader", "Modules", "Classes"])
    
    css = '''
    <style>
        .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
            font-size: 20px;
        }
    </style>
    '''
    st.markdown(css, unsafe_allow_html=True)

    with basic:
        await basic_info(app, session, pid, device)
    with script_loader:
        await run_script_loader(app, session, pid, device)
    with storage_comp:
        await storage_func(app, session, pid, device)
    with classes:
    	await get_classes(app, session, pid, device)
    with modules:
    	await get_modules(app, session, pid, device)


