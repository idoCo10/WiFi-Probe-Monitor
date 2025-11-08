#!/usr/bin/env bash
# version: 1.2, 11/11/2025

UN=${SUDO_USER:-$(whoami)}
targets_path="/home/$UN/Desktop"
OUI_FILE="$targets_path/oui.txt"

declare -A device_ssids        # APs per device (array-like string separated by ||)
declare -A device_macs         # Vendor per device
declare -A device_first_seen   # First seen timestamp per device
declare -A vendor_cache        # OUI cache
declare -A missing_devices     # devices with missing/wildcard probes
declare -A missing_first_seen  # first seen time for missing devices

# Colors
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
ORANGE=$'\033[1;33m'
BLUE=$'\033[1;34m'
CYAN=$'\033[1;36m'
RESET=$'\033[0m'
BOLD=$'\033[1m'

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "${RED}Please run this script as root or with sudo.${RESET}"
  exit 1
fi

check_oui() {
    if [ ! -f "$OUI_FILE" ]; then
        echo "${ORANGE}Downloading OUI vendor file...${RESET}"
        wget -q https://raw.githubusercontent.com/idoCo10/OUI-list-2025/main/oui.txt -O "$OUI_FILE"
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

    if [[ "$wifi_adapter" != *"mon" ]]; then
        airmon-ng start "$wifi_adapter" > /dev/null 2>&1
        adapters=($(iw dev | awk '$1=="Interface"{print $2}'))
        for adapter in "${adapters[@]}"; do
            [[ "$adapter" == *"mon" ]] && wifi_adapter="$adapter"
        done
    fi
}

normalize_mac() {
    echo "$1" | tr '[:lower:]' '[:upper:]' | sed 's/[-\.]/:/g'
}

get_vendor() {
    local mac="$1"
    [[ -n "${vendor_cache[$mac]}" ]] && echo "${vendor_cache[$mac]}" && return
    local prefix=$(echo "$mac" | cut -d':' -f1-3)
    local vendor=$(grep -i "^$prefix " "$OUI_FILE" | awk '{$1=""; print substr($0,2)}')
    vendor="${vendor:-Unknown OUI}"
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

install_tshark() {
    if ! command -v tshark >/dev/null 2>&1; then
        echo "tshark not found. Installing..."
        apt update && apt install -y tshark
    fi
}

check_oui
install_tshark
adapter_config

tshark -i "$wifi_adapter" -Y "wlan.fc.type_subtype == 4" -T fields -e frame.time -e wlan.sa -e wlan.ta -e wlan.ssid -l 2>/dev/null \
| while IFS=$'\t' read -r time sa ta ssid_raw; do
    time=$(echo "$time" | grep -oP '\d{2}:\d{2}:\d{2}')
    sa=$(normalize_mac "$sa")
    ssid_decoded=$(decode_ssid_if_hex "$ssid_raw")
    ssid_decoded=$(echo "$ssid_decoded" | xargs)  # trim spaces

    # Treat empty or null SSIDs as missing
    [[ -z "$ssid_decoded" ]] && ssid_decoded="<MISSING>"

    vendor=$(get_vendor "$sa")

    if [[ "$ssid_decoded" == "<MISSING>" ]]; then
        # Only mark as missing if device has no valid APs
        valid_aps="${device_ssids[$sa]//||/ }"
        valid_aps=$(echo "$valid_aps" | tr -s ' ' | sed 's/  */ /g')
        has_valid=0
        for ap in $valid_aps; do
            [[ -n "$ap" && "$ap" != "1" ]] && has_valid=1 && break
        done
        [[ $has_valid -eq 0 ]] && missing_devices["$sa"]="$vendor" && [[ -z "${missing_first_seen[$sa]:-}" ]] && missing_first_seen[$sa]="$time"
    else
        [[ "$ssid_decoded" == "1" ]] && continue  # skip router APs

        if [[ -z "${device_ssids[$sa]+_}" ]]; then
            device_ssids["$sa"]="$ssid_decoded"
        else
            IFS='||' read -ra existing_array <<< "${device_ssids[$sa]}"
            skip=0
            for ex in "${existing_array[@]}"; do
                [[ "$ex" == "$ssid_decoded" ]] && skip=1 && break
            done
            [[ $skip -eq 0 ]] && device_ssids["$sa"]+="||$ssid_decoded"
        fi
        device_macs["$sa"]="$vendor"
        [[ -z "${device_first_seen[$sa]:-}" ]] && device_first_seen["$sa"]="$time"
        unset missing_devices["$sa"]
        unset missing_first_seen["$sa"]
    fi

    # Display
    clear
    echo -e "${BOLD}=== Probe Requests Live ===${RESET}"

    # Sort devices by first-seen time (oldest first)
    for dev in $(for d in "${!device_first_seen[@]}"; do
                    echo "${device_first_seen[$d]} $d"
                done | sort | awk '{print $2}'); do
        vendor="${device_macs[$dev]}"
        first_seen="${device_first_seen[$dev]}"
        echo
        echo -e "${CYAN}[$first_seen]${RESET}   ${GREEN}$dev${RESET}   |   ${ORANGE}$vendor${RESET}"

        count=1
        IFS='||' read -ra aps <<< "${device_ssids[$dev]}"
        for ap in "${aps[@]}"; do
            [[ -n "$ap" && "$ap" != "1" ]] || continue
            printf "             + ${BLUE}AP %d:${RESET} %s\n" "$count" "$ap"
            ((count++))
        done
    done

    # Missing/open devices
    if [ ${#missing_devices[@]} -gt 0 ]; then
        echo
        echo -e "${RED}Devices open for any AP:${RESET}"
        for mac in $(for m in "${!missing_devices[@]}"; do echo "${missing_first_seen[$m]} $m"; done | sort | awk '{print $2}'); do
            [[ -n "${device_ssids[$mac]:-}" ]] && continue
            first_seen="${missing_first_seen[$mac]}"
            printf "${CYAN}[%s]${RESET}   ${GREEN}%s${RESET}   |   ${ORANGE}%s${RESET}\n" "$first_seen" "$mac" "${missing_devices[$mac]}"
        done
    fi
done
