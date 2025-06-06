<img src="https://enciphers-team.github.io/mobXplore-website/assets/logo.webp" alt="MobXplore Logo" width="400" />

[![Visit MobXplore Website](https://img.shields.io/badge/Visit%20Website-MobXplore-blue?style=for-the-badge)](https://mobxplore.com)  
> **MobXplore** is brought to you by the team at [Enciphers](https://enciphers.com), experts in mobile and application security.

---

## Overview

MobXplore is a frida based, open-source tool designed to assist security researchers, developers, and pentesters in performing comprehensive mobile application security assessments. Currently built for iOS devices, mobXplore will expand its capabilities to support Android devices in later updates. It is aimed at bringing together all the functionalities and tools required while performing mobile application security assessments. It utilises Firda for most of its functionality, and it also integrate other tools for some it's functionality. It streamlines the process of mobile application penetration testing by offering a powerful yet user-friendly interface packed with essential features. Built for pentesters and developers alike, it simplifies various stages of mobile application security testing, including device information retrieval, app management, IPA extraction, quick scan and dynamic analysis using frida, etc. mobXplore offers an intuitive yet powerful interface to explore and mobile applications.

## Key Features

1. Device Information Retrieval
	- Get detailed device information, including device name, model, iOS version, UDID, serial number, etc.
	- Note: This information is retrieved using `ideviceinfo` (for USB Connection) and `frida` (for remote connection).

2. App Manager
	- List installed applications with metadata like app name, version,icon and bundle identifier, etc.
	- Explore app-specific details and interact with installed apps.
	- After selecting an app to explore you get access to:
		- General app info and Info.plist file.
		- App Classes
		- App Modules
		- Files
		- Storage Data like cookies, keychains, NSUserDefaults, etc

3. IPA Extractor
	- Extract decrypted IPA of any installed application on the device.

4. Quick Security Scan
	- A simple rule-based,runtime scanner.
	- Scan any app installed on the device.

## Connecting Your Mobile Device

MobXplore supports device connection via USB as well as remote connection. Again these connections are managed using frida internally.
`Note: You need a jailbroken iOS device with frida-agent running and also make sure you have root access to device via SSH.`
- **Connecting via USB :** Just connect you device via any of USB cable that your device supports, ideally the cable used for charging should always work.
- **Remote Connection:** Follow the below step:
	- Make sure your device is connected to same wifi network.
	- Run this command: `ssh -L 27042:localhost:27042 root@<mobile_IP> -o ServerAliveInterval=60` 
	- The above command need to be run on docker shell if using docker other if running in without docker then run on your system's terminal.
	- Run mobXplore tool and click on **Connect Remote Device** button.
- **Some Important Points:**
	- mobXplore supports single device  as of now.
	- You can connect by either of two ways, that is, via USB or remotely. 
	- If device is connected via USB then option for remote device connection won't show up in UI.
	- When connecting remotely, make sure you have an active SSH session.

## Installing & Using mobXplore
- ### Using Docker
	
	Follow these steps:
	```bash
	git clone https://github.com/enciphers-team/mobXplore
	cd mobXplore
	docker build -t mobexplore:latest . 
	docker run -d -p 8501:8501 mobexplore:latest
	
	#Then Access the application on:- http://localhost:8501
	```
	**Note:-** While using mobXplore using docker, prefer connecting your device remotely, but if you still want to connect your mobile device using USB then **Linux** users can use this command to run the tool:
	```bash
	docker run -d -p 8501:8501 mobexplore:latest -v /var/run:/var/run
	```
	If you are on **Windows** or **MacOS**	and want to connect your mobile device using USB, then you have to use a linux VM with access to the USB port you want to use to connect to your device because passing the mobile device connected to host to a docker container is not possible.

- ### Without Docker
	 It is possible to run mobXplore without using docker, but as of now this has only been tested on **Linux** and **MacOS**, and won't work on **Windows** with current version.
	 
	 Follow these steps to install without docker:
`Note: Make sure you have python3 and pip instaled. Also make sure that`**ideviceinfo** `command works on your system while the mobile device is connected via USB.`
	```bash
	git clone https://github.com/enciphers-team/mobXplore
	cd mobXplore
	python3 -m venv mobxplore_venv
	source  mobxplore_venv/bin/activate
	pip3  install  -r  requirements.txt
	streamlit run main.py
	
	#Then Access the application on:- http://localhost:8501
	```
