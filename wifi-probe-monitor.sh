#!/usr/bin/env bash
# version: 1.4, 11/11/2025 05:34

UN=${SUDO_USER:-$(whoami)}
targets_path="/home/$UN/Desktop"
OUI_FILE="$targets_path/oui.txt"
declare -A device_ssids        # APs per device (array-like string separated by ||)
declare -A device_macs         # Vendor per device
declare -A device_first_seen   # First seen timestamp per device
declare -A vendor_cache        # OUI cache
declare -A missing_devices     # devices with missing/wildcard probes
declare -A missing_first_seen  # first seen time for missing devices
declare -A device_ssid_counts  # count of how many times device probed each SSID
declare -A missing_counts      # count of how many times device sent <MISSING> probe
declare -A ap_details_cache    # Cache for AP details (MAC, encryption, channel, power)

# Colors
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
ORANGE=$'\033[1;33m'
BLUE=$'\033[1;34m'
CYAN=$'\033[1;36m'
NEON_YELLOW=$'\033[38;5;226m'
NEON_GREEN=$'\033[38;5;82m'
NEON_PURPLE=$'\033[38;5;201m'
RESET=$'\033[0m'
BOLD=$'\033[1m'

# Global variables for cleanup
WIFI_ADAPTER=""
ORIGINAL_ADAPTER=""
CLEANUP_DONE=false

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "${RED}Please run this script as root or with sudo.${RESET}"
    exit 1
fi

# Cleanup function
cleanup() {
    # Prevent multiple cleanup executions
    if [[ "$CLEANUP_DONE" == true ]]; then
        return
    fi
    CLEANUP_DONE=true
    
    echo
    echo "${BLUE}Cleaning up processes and network interfaces...${RESET}"
    
    # Kill any airodump-ng processes
    echo "Stopping any airodump-ng processes..."
    pkill -f "airodump-ng" >/dev/null 2>&1
    sleep 1
    pkill -9 -f "airodump-ng" >/dev/null 2>&1
    
    # Clean up temporary files
    echo "Cleaning temporary files..."
    rm -f "/tmp/ap_scan_$$"* >/dev/null 2>&1
    
    # Stop monitor mode and restore original interface
    if [[ -n "$WIFI_ADAPTER" && "$WIFI_ADAPTER" == *"mon" ]]; then
        echo "Stopping monitor mode on $WIFI_ADAPTER"
        airmon-ng stop "$WIFI_ADAPTER" >/dev/null 2>&1
    fi
    
    # Restart network manager
    echo "Restarting network services..."
    systemctl restart NetworkManager >/dev/null 2>&1 || service network-manager restart >/dev/null 2>&1
    
    echo "${GREEN}Cleanup completed.${RESET}"
    exit 0
}

# Set trap for Ctrl+C and other signals
trap cleanup INT TERM EXIT

check_oui() {
    if [ ! -f "$OUI_FILE" ]; then
        echo "${ORANGE}Downloading OUI vendor file...${RESET}"
        wget -q https://raw.githubusercontent.com/idoCo10/OUI-list/main/oui.txt -O "$OUI_FILE"
        [[ ! -f "$OUI_FILE" ]] && { echo "${RED}Failed to download OUI vendor file.${RESET}"; exit 1; }
    fi
}

adapter_config() {
    airmon-ng check kill > /dev/null 2>&1
    adapters=($(iw dev | awk '$1=="Interface"{print $2}'))
    if [[ ${#adapters[@]} -eq 0 ]]; then
        read -p "Enter your WiFi adapter name: " wifi_adapter
        [[ -z "$wifi_adapter" ]] && { echo "${RED}No adapter provided. Exiting.${RESET}"; exit 1; }
    elif [[ ${#adapters[@]} -eq 1 ]]; then
        wifi_adapter="${adapters[0]}"
    else
        echo "Detected adapters:"
        for i in "${!adapters[@]}"; do
            echo "$((i+1))) ${adapters[$i]}"
        done
        read -p "Select adapter by number or name: " input
        if [[ "$input" =~ ^[0-9]+$ && "$input" -ge 1 && "$input" -le ${#adapters[@]} ]]; then
            wifi_adapter="${adapters[$((input-1))]}"
        else
            wifi_adapter="$input"
        fi
    fi
    
    ORIGINAL_ADAPTER="$wifi_adapter"
    
    if [[ "$wifi_adapter" != *"mon" ]]; then
        airmon-ng start "$wifi_adapter" > /dev/null 2>&1
        adapters=($(iw dev | awk '$1=="Interface"{print $2}'))
        for adapter in "${adapters[@]}"; do
            [[ "$adapter" == *"mon" ]] && wifi_adapter="$adapter"
        done
    fi
    
    WIFI_ADAPTER="$wifi_adapter"
}

normalize_mac() {
    echo "$1" | tr '[:lower:]' '[:upper:]' | sed 's/[-\.]/:/g'
}

get_vendor() {
    local mac="$1"
    [[ -n "${vendor_cache[$mac]}" ]] && echo "${vendor_cache[$mac]}" && return
    
    local prefix=$(echo "$mac" | cut -d':' -f1-3)
    local vendor=$(grep -i "^$prefix " "$OUI_FILE" | awk '{$1=""; print substr($0,2)}')
    vendor="${vendor:-}"
    vendor_cache[$mac]="$vendor"
    echo "$vendor"
}

decode_ssid_if_hex() {
    local ssid="$1"
    if [[ "$ssid" =~ ^[0-9A-Fa-f]+$ && $(( ${#ssid} % 2 )) -eq 0 ]]; then
        local decoded
        decoded="$(echo "$ssid" | xxd -r -p 2>/dev/null || true)"
        [[ -n "$decoded" && "$decoded" =~ [[:print:]] ]] && echo "$decoded" && return
    fi
    echo "$ssid"
}

install_dependencies() {
    if ! command -v tshark >/dev/null 2>&1; then
        echo "tshark not found. Installing..."
        apt update && apt install -y tshark
    fi
    
    if ! command -v airodump-ng >/dev/null 2>&1; then
        echo "airodump-ng not found. Installing..."
        apt update && apt install -y aircrack-ng
    fi
}

get_ap_details() {
    local ssid="$1"
    local iface="$2"
    
    # Check cache first
    [[ -n "${ap_details_cache[$ssid]}" ]] && echo "${ap_details_cache[$ssid]}" && return
    
    local temp_output="/tmp/ap_scan_$$"
    local temp_csv="${temp_output}-01.csv"
    
    # Clean up any existing files
    rm -f "${temp_output}"* >/dev/null 2>&1
    
    # Start airodump-ng in background
    sudo airodump-ng --band abg "$iface" --essid "$ssid" --ignore-negative-one --output-format csv -w "$temp_output" >/dev/null 2>&1 &
    local airo_pid=$!
    
    local bssid="" channel="" encryption="" power=""
    local max_attempts=10
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if [ -f "$temp_csv" ]; then
            # Find the AP line for the SSID
            local ap_line=$(awk -F',' -v target_ssid="$ssid" '
            NR>1 {
                gsub(/^ +| +$/,"",$14)
                if($14==target_ssid && $1!="" && $1!~/" "/){
                    print $1","$4","$6","$9
                    exit
                }
            }' "$temp_csv" 2>/dev/null)
            
            if [ -n "$ap_line" ]; then
                IFS=',' read -r bssid channel encryption power <<< "$ap_line"
                # Trim spaces
                bssid=$(echo "$bssid" | xargs)
                channel=$(echo "$channel" | xargs)
                encryption=$(echo "$encryption" | xargs)
                power=$(echo "$power" | xargs)
                
                # Validate we got reasonable data
                if [[ -n "$bssid" && "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                    break
                fi
            fi
        fi
        sleep 1
        ((attempt++))
    done
    
    # Stop airodump-ng
    sudo kill $airo_pid >/dev/null 2>&1
    wait $airo_pid 2>/dev/null
    
    # Clean up temp files
    rm -f "${temp_output}"* >/dev/null 2>&1
    
    # Set default values if not found
    bssid="${bssid:--}"
    channel="${channel:--}"
    encryption="${encryption:--}"
    power="${power:--}"
    
    local result="${bssid}|${encryption}|${channel}|${power}"
    ap_details_cache[$ssid]="$result"
    echo "$result"
}

# Main execution
check_oui
install_dependencies
adapter_config

clear
echo "${ORANGE}Starting probe requests monitoring on ${NEON_GREEN}$WIFI_ADAPTER${ORANGE}...${RESET}"
#echo "${CYAN}Press Ctrl+C to stop and cleanup...${RESET}"

# Use the original working pipeline
tshark -i "$WIFI_ADAPTER" -Y "wlan.fc.type_subtype == 4" -T fields -e frame.time -e wlan.sa -e wlan.ta -e wlan.ssid -l 2>/dev/null \
| while IFS=$'\t' read -r time sa ta ssid_raw; do
    time=$(echo "$time" | grep -oP '\d{2}:\d{2}:\d{2}')
    sa=$(normalize_mac "$sa")
    ssid_decoded=$(decode_ssid_if_hex "$ssid_raw")
    ssid_decoded=$(echo "$ssid_decoded" | xargs) # trim spaces
    [[ -z "$ssid_decoded" ]] && ssid_decoded="<MISSING>"
    
    vendor=$(get_vendor "$sa")
    
    if [[ "$ssid_decoded" == "<MISSING>" ]]; then
        ((missing_counts["$sa"]++))
        valid_aps="${device_ssids[$sa]//||/ }"
        has_valid=0
        for ap in $valid_aps; do
            [[ -n "$ap" && "$ap" != "1" ]] && has_valid=1 && break
        done
        
        if [[ $has_valid -eq 0 ]]; then
            missing_devices["$sa"]="$vendor"
            [[ -z "${missing_first_seen[$sa]:-}" ]] && missing_first_seen[$sa]="$time"
        fi
    else
        [[ "$ssid_decoded" == "1" ]] && continue
        
        IFS='||' read -ra existing_array <<< "${device_ssids[$sa]:-}"
        found=0
        for ex in "${existing_array[@]}"; do
            if [[ "$ex" == "$ssid_decoded" ]]; then
                found=1
                key="${sa}_${ssid_decoded}"
                ((device_ssid_counts["$key"]++))
                break
            fi
        done
        
        if [[ $found -eq 0 ]]; then
            # New SSID for this device - get AP details
            #sleep 1
            ap_details=$(get_ap_details "$ssid_decoded" "$WIFI_ADAPTER")
            IFS='|' read -r ap_mac ap_encryption ap_channel ap_power <<< "$ap_details"
            
            # Store AP details in cache for display
            ap_details_cache["$ssid_decoded"]="$ap_details"
            
            if [[ -z "${device_ssids[$sa]+_}" ]]; then
                device_ssids["$sa"]="$ssid_decoded"
            else
                device_ssids["$sa"]+="||$ssid_decoded"
            fi
            key="${sa}_${ssid_decoded}"
            device_ssid_counts["$key"]=1
        fi
        
        device_macs["$sa"]="$vendor"
        [[ -z "${device_first_seen[$sa]:-}" ]] && device_first_seen["$sa"]="$time"
        unset missing_devices["$sa"]
        unset missing_first_seen["$sa"]
    fi
    
    # Display - KEEP THE ORIGINAL WORKING FORMAT
    clear
    echo -e "${BOLD}=== Probe Requests Live ===${RESET}"
    
    # Sort devices by first-seen time (oldest first)
    for dev in $(for d in "${!device_first_seen[@]}"; do echo "${device_first_seen[$d]} $d"; done | sort | awk '{print $2}'); do
        vendor="${device_macs[$dev]}"
        first_seen="${device_first_seen[$dev]}"
        echo
        echo -e "[$first_seen]  ${NEON_GREEN}${BOLD}$dev${RESET}       |  ${ORANGE}$vendor${RESET}"
        count=1
        IFS='||' read -ra aps <<< "${device_ssids[$dev]}"
        for ap in "${aps[@]}"; do
            [[ -n "$ap" && "$ap" != "1" ]] || continue
            
            key="${dev}_${ap}"
            hits="${device_ssid_counts[$key]:-1}"
            
            # Get AP details from cache - USE ORIGINAL WORKING FORMAT
            if [[ -n "${ap_details_cache[$ap]}" ]]; then
                IFS='|' read -r ap_mac ap_encryption ap_channel ap_power <<< "${ap_details_cache[$ap]}"
                printf "             + ${RED}AP %d:${RESET}  ${BOLD}%-17s${RESET}\n" "$count" "$ap"       
                printf "               ${CYAN}BSSID: %-17s  Enc: %-8s  Ch: %-3s  Pwr: %-4s${RESET}\n" \
                       "$ap_mac" "$ap_encryption" "$ap_channel" "$ap_power"
                printf "               ${NEON_PURPLE}${BOLD}(%s)${RESET}\n" "$hits"         
                       
            else
                printf "             + ${RED}AP %d:${RESET} ${BOLD}%s${RESET} ${CYAN}(%s)${RESET}\n" "$count" "$ap" "$hits"
            fi
            ((count++))
        done
    done
    
    # Missing/open devices
    if [ ${#missing_devices[@]} -gt 0 ]; then
        echo
        echo -e "${NEON_YELLOW}${BOLD}Devices open for any AP:${RESET}"
        for mac in $(for m in "${!missing_devices[@]}"; do echo "${missing_first_seen[$m]} $m"; done | sort | awk '{print $2}'); do
            [[ -n "${device_ssids[$mac]:-}" ]] && continue
            first_seen="${missing_first_seen[$mac]}"
            hits="${missing_counts[$mac]:-1}"
            printf "[%s]  ${NEON_GREEN}${BOLD}%s${RESET}  ${NEON_PURPLE}${BOLD}(${hits})${RESET}  |  ${ORANGE}%s${RESET}\n" "$first_seen" "$mac" "${missing_devices[$mac]}"
        done
    fi
done
