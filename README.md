# threat-hunting-scenario-Tor

# Official Cyber Range Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/brian-conor-sanford/threat-hunting-scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "b_user" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `torwebshopping.txt` on the desktop. These events began at `2025-10-12T00:46:51.1497979Z`.

**Query used to locate events:**

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "vm-mde-b"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "b_user"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1072" height="377" alt="Screenshot 2025-10-21 at 8 45 38 PM" src="https://github.com/user-attachments/assets/95a967f3-a70d-4051-a70a-12025fe6c899" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.8.exe". Based on the logs returned b_user on the "vm-mde-b" device ran the file `tor-browser-windows-x86_64-portable-14.5.8.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-mde-b"
| where ProcessCommandLine contains "tor"
| project Timestamp, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1064" height="34" alt="Screenshot 2025-10-21 at 9 02 02 PM" src="https://github.com/user-attachments/assets/f7db40e0-2a93-41ff-9d3b-8cc27b022fc2" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "b_user" actually opened the TOR browser. There was evidence that they did open it at `2025-10-12T00:46:51.1497979Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "vm-mde-b"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1069" height="167" alt="Screenshot 2025-10-21 at 9 09 59 PM" src="https://github.com/user-attachments/assets/d7a9d3e5-d0cb-4adc-b213-1c30bf3f1499" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-10-12T00:46:51.1497979Z`, b_user on the "vm-mde-b" device successfully established a connection to the remote IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `tor.exe`, there was at least one connection. There were a couple of other connections using the ports 80 and 443
.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-mde-b"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath
```
<img width="986" height="99" alt="Screenshot 2025-10-21 at 9 07 44 PM" src="https://github.com/user-attachments/assets/058d37ea-ad1c-403a-86d2-0180d5030c01" />

---

## Chronological Event Timeline 

### 1. Tor Browser Download
**Description:**  
User `b_user` downloaded `tor-browser-windows-x86_64-portable-14.5.8.exe` from an external source, indicating intentional acquisition of the TOR Browser package.

---

### 2. Tor Browser Installation
**Description:**  
The downloaded installer was executed, unpacking TOR Browser files within the user directory (`C:\Users\b_user\Desktop\Tor Browser\`).  
This confirms a successful **local installation**.

---

### 3. Tor Browser Execution and Network Activity
**Description:**  
`firefox.exe` (within the TOR Browser folder) initiated a local connection to `127.0.0.1:9150`, the TOR SOCKS proxy port.  
This confirms that the TOR Browser was **actively used** and successfully connected to the TOR network.


---

##  Summary

Between **5:46–5:56 PM (Oct 11, 2025, Phoenix time)**, user `b_user` on `vm-mde-b`:
- Silently installed the TOR Browser (`/S` flag)  
- Created TOR-related files including `torwebshopping.txt`  
- Opened the TOR Browser and spawned `tor.exe` processes  
- Established both **local (127.0.0.1:9150)** and **external (80/443)** network connections  
- Likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

##  Response Taken

- Confirmed TOR usage on endpoint `vm-mde-b` by `b_user`  
- Device was **isolated** from the network  
- User’s **direct manager notified** for further action 

---
**Report Author:** Brian Sanford 
**Date:** _October 2025_ 
