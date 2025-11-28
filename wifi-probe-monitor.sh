#!/usr/bin/env bash
# version: 1.9, 29/11/2025 02:44 


UN=${SUDO_USER:-$(whoami)}
targets_path="/home/$UN/Desktop/wifi-probe-monitor"
mkdir -p "$targets_path"
OUI_FILE="$targets_path/oui.txt"
AIRODUMP_FILE="$targets_path/airodump_scan.csv"

SCRIPT_START_TIME=$(date +'%d/%m/%y %H:%M:%S')
declare -A device_ssids # APs per device (array-like string separated by ||)
declare -A device_macs # Vendor per device
declare -A device_first_seen # First seen timestamp per device
declare -A vendor_cache # OUI cache
declare -A device_ssid_counts # count of how many times device probed each SSID
declare -A ap_details_cache # Cache for AP details (MAC, encryption, channel, power)
declare -A device_power # Power level per device

# Colors
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
ORANGE=$'\033[1;33m'
BLUE=$'\033[1;34m'
CYAN=$'\033[1;36m'
WHITE=$'\033[1;37m'
NEON_YELLOW=$'\033[38;5;226m'
NEON_GREEN=$'\033[38;5;82m'
NEON_PURPLE=$'\033[38;5;201m'
RESET=$'\033[0m'
BOLD=$'\033[1m'

# Global variables for cleanup
WIFI_ADAPTER=""
ORIGINAL_ADAPTER=""
CLEANUP_DONE=false
AIRODUMP_PID=""

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root or with sudo.${RESET}"
    exit 1
fi

# Enhanced cleanup function
cleanup() {
    # Prevent multiple cleanup executions
    if [[ "$CLEANUP_DONE" == true ]]; then
        return
    fi
    CLEANUP_DONE=true
    
    echo
    echo -e "\n${RED}Cleaning up processes and network interfaces...${RESET}"
    
    # Kill airodump-ng process
    echo "Stopping airodump-ng process..."
    if [[ -n "$AIRODUMP_PID" ]]; then
        kill "$AIRODUMP_PID" >/dev/null 2>&1
    fi
    pkill -f "airodump-ng" >/dev/null 2>&1
    sleep 1
    pkill -9 -f "airodump-ng" >/dev/null 2>&1
    
    # Clean up temporary files (but NOT the scan file)
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
    if ! command -v airodump-ng >/dev/null 2>&1; then
        echo "airodump-ng not found. Installing..."
        apt update && apt install -y aircrack-ng
    fi
}

start_airodump_scan() {
    echo "${ORANGE}Starting airodump-ng scan on $WIFI_ADAPTER...${RESET}"
    
    # Remove any existing airodump files
    rm -f "$AIRODUMP_FILE"* >/dev/null 2>&1
    
    # Start airodump-ng in background
    airodump-ng "$WIFI_ADAPTER" --band abg --ignore-negative-one --output-format csv -w "$AIRODUMP_FILE" >/dev/null 2>&1 &
    AIRODUMP_PID=$!
    
    # Wait for CSV file to be created
    local max_wait=10
    local wait_count=0
    while [[ ! -f "${AIRODUMP_FILE}-01.csv" && $wait_count -lt $max_wait ]]; do
        sleep 1
        ((wait_count++))
    done
    
    if [[ ! -f "${AIRODUMP_FILE}-01.csv" ]]; then
        echo "${RED}Failed to start airodump-ng scan${RESET}"
        exit 1
    fi
    
    echo "${GREEN}Airodump-ng scan started successfully (PID: $AIRODUMP_PID)${RESET}"
}

parse_probe_requests() {
    local csv_file="${AIRODUMP_FILE}-01.csv"
    
    if [[ ! -f "$csv_file" ]]; then
        return
    fi
    
    # Use process substitution to avoid subshell issues
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Extract fields manually to handle commas in probed ESSIDs
        station_mac=$(echo "$line" | cut -d',' -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        first_seen=$(echo "$line" | cut -d',' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        power=$(echo "$line" | cut -d',' -f4 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        packets_count=$(echo "$line" | cut -d',' -f5 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Get everything from field 7 to the end as probed ESSIDs
        probed_essids=$(echo "$line" | cut -d',' -f7- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/,$//')
        
        # Skip incomplete records or header
        [[ -z "$station_mac" || "$station_mac" == "Station MAC" || ! "$station_mac" =~ ":" ]] && continue
        
        # Normalize MAC
        station_mac=$(normalize_mac "$station_mac")
        
        # Get vendor
        vendor=$(get_vendor "$station_mac")
        
        # Extract time from first_seen (remove date part)
        first_seen_time=$(echo "$first_seen" | grep -oP '\d{2}:\d{2}:\d{2}' | head -1)
        [[ -z "$first_seen_time" ]] && first_seen_time="$(date +%H:%M:%S)"
        
        # Only process if we have probed ESSIDs and they are not "(not associated)"
        if [[ -n "$probed_essids" && "$probed_essids" != "(not associated)" ]]; then
            # Split multiple ESSIDs by comma and process each one
            IFS=',' read -ra essid_array <<< "$probed_essids"
            for essid in "${essid_array[@]}"; do
                # Clean up each individual ESSID
                essid_clean=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [[ -z "$essid_clean" ]] && continue
                
                # Decode if hex
                essid_decoded=$(decode_ssid_if_hex "$essid_clean")
                
                # Skip empty or generic probes
                if [[ -n "$essid_decoded" && "$essid_decoded" != "<MISSING>" && "$essid_decoded" != "Broadcast" && "$essid_decoded" != "(not associated)" ]]; then
                    # Check if this is a new SSID for this device
                    IFS='||' read -ra existing_array <<< "${device_ssids[$station_mac]:-}"
                    found=0
                    for ex in "${existing_array[@]}"; do
                        if [[ "$ex" == "$essid_decoded" ]]; then
                            found=1
                            key="${station_mac}_${essid_decoded}"
                            # Update probe count from CSV
                            device_ssid_counts["$key"]=$packets_count
                            break
                        fi
                    done
                    
                    if [[ $found -eq 0 ]]; then
                        # New SSID for this device
                        if [[ -z "${device_ssids[$station_mac]+_}" ]]; then
                            device_ssids["$station_mac"]="$essid_decoded"
                        else
                            device_ssids["$station_mac"]+="||$essid_decoded"
                        fi
                        key="${station_mac}_${essid_decoded}"
                        # Store probe count from CSV
                        device_ssid_counts["$key"]=$packets_count
                        
                        # Store device info
                        device_macs["$station_mac"]="$vendor"
                        # Store first seen time from CSV
                        device_first_seen["$station_mac"]="$first_seen_time"
                        # Store power from CSV
                        device_power["$station_mac"]="$power"
                    else
                        # For existing SSIDs, make sure device info is set
                        device_macs["$station_mac"]="$vendor"
                        # Update first seen time if not set
                        [[ -z "${device_first_seen[$station_mac]:-}" ]] && device_first_seen["$station_mac"]="$first_seen_time"
                        # Update power if not set
                        [[ -z "${device_power[$station_mac]:-}" ]] && device_power["$station_mac"]="$power"
                    fi
                fi
            done
        fi
    done < <(
        # Find the line number where the station list starts
        local station_start_line=$(grep -n "Station MAC" "$csv_file" | cut -d: -f1)
        
        if [[ -n "$station_start_line" ]]; then
            # Output only the station lines (skip header)
            tail -n +$((station_start_line + 1)) "$csv_file"
        fi
    )
}

update_ap_cache_from_airodump() {
    local csv_file="${AIRODUMP_FILE}-01.csv"
    
    if [[ ! -f "$csv_file" ]]; then
        return
    fi
    
    # Find the line number where the station list starts
    local station_start_line=$(grep -n "Station MAC" "$csv_file" | cut -d: -f1)
    
    if [[ -z "$station_start_line" ]]; then
        station_start_line=999999
    fi
    
    # Parse AP section using awk - similar to your working approach
    awk -F, -v station_line="$station_start_line" '
    NR >= station_line { exit }
    /BSSID/ { next }
    $1 ~ /:/ && $14 != "" {
        bssid = $1
        essid = $14
        channel = $4
        privacy = $6
        power = $9
        
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", bssid)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", essid)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", channel)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", privacy)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", power)
        
        if (essid != "") {
            print essid "|" bssid "|" privacy "|" channel "|" power
        }
    }
    ' "$csv_file" | while IFS='|' read -r essid bssid privacy channel power; do
        [[ -z "$essid" ]] && continue
        
        # Decode if hex
        essid_decoded=$(decode_ssid_if_hex "$essid")
        
        # Update AP cache
        if [[ -n "$essid_decoded" && "$essid_decoded" != "<MISSING>" ]]; then
            ap_details_cache["$essid_decoded"]="${bssid}|${privacy}|${channel}|${power}"
        fi
    done
}




# Display function - shows devices probing for specific APs in table format with AP details
display_results() {
    clear
    echo -e "${ORANGE}======== WiFi Probe Monitor ========${RESET}"
    echo -e "${BOLD}Start time: $SCRIPT_START_TIME${RESET}\n\n"
    
    if [ ${#device_first_seen[@]} -eq 0 ]; then
        echo -e "${NEON_YELLOW}No devices probing for specific APs detected yet...${RESET}"
        echo -e "\n\n${CYAN}Press Ctrl+C to stop the scan${RESET}"
        return
    fi
    
    # Display header with AP details
    printf "${BOLD}%-3s %-18s %-43s %-8s %-8s %-28s %-18s %-10s %-9s %-11s %-30s${RESET}\n" \
        "#" "Device" "Device OUI" "Power" "Probes" "AP Name" "MAC" "AP power" "Channel" "Encryption" "AP OUI"
    echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    # Define color array for multiple AP devices
    local multi_ap_colors=("${NEON_GREEN}" "${NEON_PURPLE}" "${CYAN}" "${ORANGE}" "${RED}" "${BLUE}" "${NEON_YELLOW}")
    
    # Create an associative array to track colors for each multi-AP device
    declare -A device_colors
    local color_index=0
    
    # First pass: assign colors to devices with multiple APs
    for dev in "${!device_first_seen[@]}"; do
        IFS='||' read -ra aps <<< "${device_ssids[$dev]}"
        local ap_count=${#aps[@]}
        if [[ $ap_count -gt 1 ]]; then
            device_colors["$dev"]="${multi_ap_colors[$color_index]}"
            color_index=$(( (color_index + 1) % ${#multi_ap_colors[@]} ))
        fi
    done
    
    # Sort devices by first-seen time (oldest first) and display with numbers
    local count=1
    for dev in $(for d in "${!device_first_seen[@]}"; do echo "${device_first_seen[$d]} $d"; done | sort | awk '{print $2}'); do
        vendor="${device_macs[$dev]}"
        power="${device_power[$dev]:--}"
        
        IFS='||' read -ra aps <<< "${device_ssids[$dev]}"
        local ap_count=${#aps[@]}
        
        # Get color for this device (if it has multiple APs)
        local device_color=""
        if [[ $ap_count -gt 1 ]]; then
            device_color="${device_colors[$dev]}"
        fi
        
        for ap in "${aps[@]}"; do
            [[ -n "$ap" && "$ap" != "1" ]] || continue
            key="${dev}_${ap}"
            probe_count="${device_ssid_counts[$key]:-0}"
            
            # Search for AP details in the airodump file
            ap_details=$(get_ap_details "$ap")
            
            # Extract AP details
            ap_mac=$(echo "$ap_details" | cut -d'|' -f1)
            ap_power=$(echo "$ap_details" | cut -d'|' -f2)
            ap_channel=$(echo "$ap_details" | cut -d'|' -f3)
            ap_encryption=$(echo "$ap_details" | cut -d'|' -f4)
            ap_vendor=$(echo "$ap_details" | cut -d'|' -f5)
            
            # Set empty values if AP not found
            [[ -z "$ap_mac" || "$ap_mac" == "Not Found" ]] && ap_mac=""
            [[ -z "$ap_power" ]] && ap_power=""
            [[ -z "$ap_channel" ]] && ap_channel=""
            [[ -z "$ap_encryption" ]] && ap_encryption=""
            [[ -z "$ap_vendor" ]] && ap_vendor=""
            
            # Color the device MAC based on whether it probes for multiple APs
            if [[ -n "$device_color" ]]; then
                printf "%-3s ${device_color}%-18s${RESET} %-43s %-8s %-8s %-28s %-18s %-10s %-9s %-11s %-30s\n" \
                    "${count})" "$dev" "$vendor" "$power" "$probe_count" "$ap" "$ap_mac" "$ap_power" "$ap_channel" "$ap_encryption" "$ap_vendor"
            else
                printf "%-3s %-18s %-43s %-8s %-8s %-28s %-18s %-10s %-9s %-11s %-30s\n" \
                    "${count})" "$dev" "$vendor" "$power" "$probe_count" "$ap" "$ap_mac" "$ap_power" "$ap_channel" "$ap_encryption" "$ap_vendor"
            fi
            
            ((count++))
        done
    done
    
    echo -e "\n\n${CYAN}Press Ctrl+C to stop the scan${RESET}"
}
# Function to get AP details from airodump file
get_ap_details() {
    local ap_essid="$1"
    local csv_file="${AIRODUMP_FILE}-01.csv"
    
    if [[ ! -f "$csv_file" ]]; then
        echo "||||"
        return
    fi
    
    # Find the line number where the station list starts (to know where AP section ends)
    local station_start_line=$(grep -n "Station MAC" "$csv_file" | cut -d: -f1)
    
    if [[ -z "$station_start_line" ]]; then
        station_start_line=999999
    fi
    
    # Search for AP in the AP section of the CSV
    local ap_line=$(awk -F, -v target_essid="$ap_essid" -v station_line="$station_start_line" '
    NR >= station_line { exit }
    /BSSID/ { next }
    $1 ~ /:/ {
        # Field 14 is ESSID, but we need to clean it
        essid = $14
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", essid)
        gsub(/,$/, "", essid)  # Remove trailing comma if present
        
        if (essid == target_essid) {
            bssid = $1
            channel = $4
            encryption = $6
            power = $9
            
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", bssid)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", channel)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", encryption)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", power)
            
            print bssid "|" power "|" channel "|" encryption
            exit
        }
    }
    ' "$csv_file")
    
    if [[ -n "$ap_line" ]]; then
        # Extract BSSID from the AP line to get vendor
        local ap_bssid=$(echo "$ap_line" | cut -d'|' -f1)
        local ap_vendor=""
        
        if [[ -n "$ap_bssid" && "$ap_bssid" != "Not Found" ]]; then
            # Normalize MAC and get vendor
            local ap_bssid_norm=$(normalize_mac "$ap_bssid")
            ap_vendor=$(get_vendor "$ap_bssid_norm")
            [[ -z "$ap_vendor" ]] && ap_vendor=""
        else
            ap_vendor=""
        fi
        
        echo "${ap_line}|${ap_vendor}"
    else
        echo "||||"
    fi
}



# Main execution
check_oui
install_dependencies
adapter_config
start_airodump_scan

clear
echo "${ORANGE}Starting probe requests monitoring via airodump-ng on ${NEON_GREEN}$WIFI_ADAPTER${ORANGE}...${RESET}"
echo "${ORANGE}Airodump-ng PID: $AIRODUMP_PID${RESET}"
echo "${ORANGE}Output file: ${AIRODUMP_FILE}-01.csv${RESET}"
echo "${ORANGE}Display will update every 5 seconds${RESET}"
echo

# Main monitoring loop
while true; do
    # Parse probe requests from airodump output
    parse_probe_requests
    
    # Update AP cache from airodump output
    update_ap_cache_from_airodump
    
    # Display results
    display_results
    
    # Wait 5 seconds before next update
    sleep 5
done
