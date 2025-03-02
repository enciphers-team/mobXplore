import streamlit as st
import frida
import subprocess
import re
import paramiko
from paramiko import SSHClient
from scp import SCPClient
import tempfile
import os
import threading
import shutil, codecs
from tqdm import tqdm
import sys

IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')
    
TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
DUMP_JS = "scripts/dump.js"
file_dict = {}
output_ipa = None
ssh = None

finished = threading.Event()

def create_dir(path):
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)

def load_js_file(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

    return script

def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in device.enumerate_applications():
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            device.resume(pid)
        else:
            session = device.attach(pid)
    except Exception as e:
        print(e) 

    return session, display_name, bundle_identifier

def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'

    print('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
        print("IPA Extraction Completed.")
    except Exception as e:
        print(e)
        finished.set()

def start_dump(session, ipa_name):
    # print('Dumping {} to {}'.format(display_name, TEMP_DIR))

    script = load_js_file(session, DUMP_JS)
    script.post('dump')
    finished.wait()

    generate_ipa(PAYLOAD_PATH, ipa_name)

    if session:
        session.detach()

def ipa_manager():
    # st.header("IPA Manager")
    
    st.markdown(
    f"""
    <h1 style='text-align: center;'>IPA Manager</h1>
    
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
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                ip_address = st.text_input("IP Address", placeholder="Enter IP Address")

            with col2:
                username = st.text_input("Username", placeholder="Enter Username", value="mobile")

            with col3:
                password = st.text_input("Password", placeholder="Enter Password", type="password")

            with col4:
                port = st.text_input("Port", placeholder="Enter Port", value=22)
            if st.button("Extract IPA"):
                extract_ipa(selected_app,ip_address,username,port,password,device)

        with st.expander("Sideload IPA",expanded=True):
            uploaded_file = st.file_uploader("Upload an IPA file to sideload", type=["ipa"])
            if uploaded_file and st.button("Sideload IPA"):
                st.write(f"Sideloading IPA: {uploaded_file.name}...")
                st.success(f"IPA {uploaded_file.name} sideloaded successfully.")
    except Exception as e:
        st.error(f"Error: {e}")

def extract_ipa(selected_app,ip_address,username,port,password,device):
    global output_ipa
    global ssh
    st.write(f"Starting the IPA extraction process for: **{selected_app}**")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, port=port, username=username, password=password)

        create_dir(PAYLOAD_PATH)
        (session, display_name, bundle_identifier) = open_target_app(device, selected_app)
        if output_ipa is None:
            output_ipa = display_name

        output_ipa = re.sub('\.ipa$', '', output_ipa)
        output_ipa = display_name
        
        if session:
            start_dump(session, output_ipa)
            print("Done")
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(e)
        print('Try specifying -H/--hostname and/or -p/--port')
    except paramiko.AuthenticationException as e:
        print(e)
        print('Try specifying -u/--username and/or -P/--password')
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))



def on_message(message, data):
    global ssh
    t = tqdm(unit='B',unit_scale=True,unit_divisor=1024,miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        baseName = os.path.basename(filename)
        if IS_PY2 or isinstance(baseName, bytes):
            t.desc = baseName.decode("utf-8")
        else:
            t.desc = baseName
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = str(dump_path)
            scp_to = str(PAYLOAD_PATH + '/')

            with SCPClient(ssh.get_transport(), progress = progress, socket_timeout = 60) as scp:
                scp.get(scp_from, scp_to)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '655', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh.get_transport(), progress = progress, socket_timeout = 60) as scp:
                scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()
    t.close()