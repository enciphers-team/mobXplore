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