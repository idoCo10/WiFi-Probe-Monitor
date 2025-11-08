# Wi-Fi-Probe-Monitor
Live Wi-Fi probe request monitor for Debian based Linux. Displays devices, their vendors, and the networks they probe for, highlighting devices open to any AP.


# WiFi Probe Monitor

A Bash script for Kali Linux to capture live Wi-Fi probe requests and display them in an organized way.  
It shows devices, their vendors (via OUI), SSIDs they probe for, and highlights devices open to any network.

## Features

- Capture live Wi-Fi probe requests using `tshark`.
- Display devices with their vendor name, first seen timestamp, and probed SSIDs.
- Highlight devices open to any network.
- Decode SSIDs from hex if needed.
- Sort devices by the number of probed SSIDs.
- Keeps track of missing probes (wildcard or unknown SSIDs).

## Requirements

- Kali Linux
- `tshark` (the script can auto-install it if missing)
- Wi-Fi adapter in monitor mode (script can switch it automatically)

## Installation

1. Clone this repository:

```bash
git clone https://github.com/idoCo10/Wi-Fi-Probe-Monitor.git
cd Wi-Fi-Probe-Monitor
