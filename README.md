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

- Debian based Linux (Kali, Ubuntu..)
- `tshark` (the script will auto-install it if missing)
- Wi-Fi adapter in monitor mode (script will switch it automatically)

## Installation

1. Clone this repository:

```bash
git clone https://github.com/idoCo10/Wi-Fi-Probe-Monitor.git
cd Wi-Fi-Probe-Monitor
sudo chmod +x wifi-probe-monitor.sh
sudo ./wifi-probe-monitor.sh
