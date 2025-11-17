# Official [(Threat-Hunting-Scenario)] Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/andrepoyser980/Threat-Hunting-Scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "labman" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-17 01:50:56Z`. These events began at `2025-11-17T01:50:56.5257501Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "windows-11-impo"
| where InitiatingProcessAccountName == "labman"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-17T01:50:56.5257501Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1454" height="854" alt="image" src="https://github.com/user-attachments/assets/e9912405-15d5-41a5-baf7-5f6b0ab16089" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-11-17T02:03:35.4941354Z`, an employee on the "windows-11-impo" device ran the file `tor-browser-windows-x86_64-portable-15.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "windows-11-impo"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.1.exe"
| project Timestamp, DeviceName,  ActionType, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1406" height="534" alt="image" src="https://github.com/user-attachments/assets/117241ae-9087-455d-a88d-26c352244ada" />



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labman" actually opened the TOR browser. There was evidence that they did open it at `2025-11-17T02:06:21.8219289Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-11-impo"
| where FileName has_any ("toe.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1418" height="821" alt="image" src="https://github.com/user-attachments/assets/0af2b7a2-fd84-4be9-ba8a-053bf82971e1" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-17T02:08:57.5888075Z`, an employee on the "windows-11-impo" device successfully established a connection to the remote IP address `83.108.59.221` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labman\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-11-impo"
| where InitiatingProcessAccountName !="system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9051", "9001", "9030", "443", "80","9150", "9040") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1382" height="414" alt="image" src="https://github.com/user-attachments/assets/81ee96b9-330e-4d8c-89f0-49f22bc0c67b" />


---

## Chronological Timeline of Events

### **1. Initial Tor File Activity**
**2025-11-17 01:50:56Z**  
- First filesystem activity containing the string `"tor"`.  
- Tor-related files and folders begin appearing on the desktop.  
- **`tor shopping list.txt` is created**, indicating user-created content tied to Tor usage.  
- This activity suggests direct, intentional interaction by the user.

---

### **2. Silent Execution of Tor Browser Installer**
**2022025-11-17 02:03:35Z**  
- User executes: **`tor-browser-windows-x86_64-portable-15.0.1.exe`**  
- Execution originates from the **Downloads** folder.  
- Command line parameters indicate a **silent run**, bypassing the normal GUI installer prompts.  

---

### **3. Tor Browser Fully Launches**
**2025-11-17 02:06:21Z**  
- Tor Browser opens successfully.  
- `tor.exe`, `firefox.exe`, and additional Tor subprocesses spawn from the Tor Browser directory.  
- Multiple browser-related processes begin repeated activity (content processes, UI processes, etc.).

---

### **4. Continued Tor-Related Process Activity**
**2025-11-17 02:17Z – 09:30Z (intermittent)**  
- Ongoing process creation tied to the Tor Browser.
- Activity includes repeated launches of:
  - `firefox.exe` (Tor Browser front-end)
  - Tor content processes
  - Tor background maintenance processes  

---

### **5. Tor Network Connections (Night Before Installation Logs)**
**2025-11-16 21:08:54Z – 21:08:58Z**  
- **tor.exe** makes multiple outbound connections to Tor relay IPs.
- Ports observed:
  - **9001** (Tor ORPort)
  - **9050 / 9051** (SOCKS / Control Ports)
  - **443** (encrypted fallback)  
- Example event:  
  - **ConnectionSuccess → 83.108.59.221:9001**  
  - Initiated by **tor.exe**  

These connections indicate **active Tor usage** prior to the file creation and installer execution recorded the next day.

---

## Key Artifacts
| Artifact | Description |
|---------|-------------|
| `tor-browser-windows-x86_64-portable-15.0.1.exe` | Portable Tor Browser installer executed silently |
| `tor shopping list.txt` | User-created file, appears during Tor install sequence |
| Tor Browser Folder on Desktop | Contained executable, configuration, and runtime files |
| `tor.exe` | Core Tor daemon responsible for network activity |
| `firefox.exe` | Tor Browser front-end process |

---

## Queries Used in the Threat Hunt

### **DeviceFileEvents – Tor File Discovery**
```kql
DeviceFileEvents
| where DeviceName == "windows-11-impo"
| where InitiatingProcessAccountName == "labman"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-17T01:50:56.5257501Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
DeviceProcessEvents – Silent Installer Execution

```
```kql
DeviceProcessEvents
| where DeviceName == "windows-11-impo"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.1.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
DeviceProcessEvents – Tor Browser Launch Events

```
```kql
DeviceProcessEvents
| where DeviceName == "windows-11-impo"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
DeviceNetworkEvents – Tor Network Traffic

```
```kql
Copy code
DeviceNetworkEvents
| where DeviceName == "windows-11-impo"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9051", "9001", "9030", "443", "80", "9150", "9040")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc

```

Conclusion
This threat hunt confirms that the Tor Browser was intentionally installed and actively used on the device. The presence of the file tor shopping list.txt further suggests purposeful engagement rather than accidental execution. The user demonstrated both installation and operational usage of Tor, including connections to known Tor relay infrastructure.
---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
