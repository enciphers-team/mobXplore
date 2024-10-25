import streamlit as st
import frida

def usb_device_connected():

	try:
		device = frida.get_usb_device()
		if device:
			flag = True
	except:
		flag = False
	return flag


def connect_remote_device():
    device_manager = frida.get_device_manager()
    device = None
    if not usb_device_connected():
        try:
            device = device_manager.add_remote_device("localhost:27042")
            st.success("Remote Device Conected")
        except Exception as e:
            st.error(f"Error Connecting Remote Device:{e}")
    return device