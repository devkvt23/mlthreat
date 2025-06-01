# Basic WiFi Beacon Frame Analyzer

## Purpose

This script captures and analyzes 802.11 WiFi beacon frames from nearby wireless networks. It displays information such as SSID (network name), BSSID (access point MAC address), channel, signal strength (RSSI), detected security protocols (Open, WEP, WPA, WPA2/WPA3), and a calculated security score with a corresponding threat level.

This tool is intended for educational and network analysis purposes only, adhering to passive analysis principles.

## Prerequisites

*   **Python 3.x**
*   **Scapy:** A Python library for packet manipulation.
*   **Wireless Adapter in Monitor Mode:** The script requires a wireless network interface capable of being put into monitor mode. The process for enabling monitor mode is OS-specific:
    *   **Linux:**
        ```bash
        sudo ip link set [your_interface_name] down
        sudo iwconfig [your_interface_name] mode monitor
        sudo ip link set [your_interface_name] up
        ```
        Replace `[your_interface_name]` with your actual wireless interface (e.g., `wlan0`, `wlp2s0`).
    *   **macOS:** Monitor mode might be enabled using `airport` command, which may create a new interface (e.g., `mon0`).
        ```bash
        sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport [your_interface_name] sniff [channel_number]
        ```
        You would then use the newly created interface (e.g., `en0` might become `mon0` after sniffing on `en0`).
    *   **Windows:** Requires specialized drivers (e.g., Npcap with support for monitor mode if your adapter allows it) and tools. Scapy on Windows might have limitations with monitor mode unless the underlying driver and Npcap setup correctly expose this functionality.

*   **Root/Administrator Privileges:** Packet sniffing typically requires elevated privileges.

## Installation

1.  **Clone the repository or download the script (`wifi_scanner.py`) and `requirements.txt`.**
2.  **Install dependencies:**
    Open a terminal or command prompt in the script's directory and run:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Identify your wireless interface name.** You can use tools like `ip addr` or `ifconfig` on Linux, `ifconfig` on macOS. The script will also list available interfaces when run.
2.  **Put your chosen wireless interface into monitor mode** (see Prerequisites section). This step is crucial.
3.  **Run the script with root/administrator privileges:**
    ```bash
    sudo python3 wifi_scanner.py
    ```
    On Windows, you might run it from an administrator command prompt.

4.  The script will list available interfaces. Enter the name of your interface that is in **monitor mode**.
5.  The script will then start sniffing for beacon frames and display information about discovered networks, including their security score and threat level.
6.  Press `Ctrl+C` to stop the script.

## Security Scoring (V1 - Encryption Focused)

The script now implements a basic security scoring mechanism based on the detected WiFi security settings. The total score (out of 100) is calculated based on:

*   **Encryption Security (40% weight):** Evaluates the strength of the encryption protocol (e.g., WPA3, WPA2-AES, WEP, Open). This is the primary driver of the score in the current version.
*   **Configuration Security (30% weight):** *Currently a placeholder.* In future versions, this will assess AP configuration aspects. For now, it contributes a neutral value to the score.
*   **Behavioral Analysis (30% weight):** *Currently a placeholder.* In future versions, this will analyze network behavior for anomalies. For now, it contributes a neutral value.

### Threat Levels

Based on the total security score, a threat level is assigned:

*   **CRITICAL (0-20):** Immediate security risk. Avoid connection if possible, or use extreme caution (e.g., trusted VPN). Likely Open, WEP, or severely misconfigured.
*   **HIGH (21-40):** Significant risk. Use only with a trusted VPN and exercise caution. May indicate older protocols like WPA-TKIP.
*   **MEDIUM (41-60):** Moderate risk. Potentially usable for general browsing with precautions (e.g., HTTPS, VPN). May indicate WPA2 with older ciphers or minor configuration concerns (once implemented).
*   **LOW (61-80):** Minimal risk. Generally suitable for most activities if WPA2-AES or better is confirmed.
*   **SECURE (81-100):** High confidence in security. Indicates strong protocols like WPA3 or well-configured WPA2-AES with enterprise authentication.

**Note:** The accuracy of the Configuration and Behavioral scores will improve as more detailed checks are implemented in future versions. Always correlate these findings with other security best practices.

## Disclaimer

⚠️ **Use responsibly and ethically.** Unauthorized scanning or attempting to access networks without permission is illegal in many jurisdictions. This tool is for passive analysis of publicly broadcast beacon frames only. Ensure you comply with all applicable laws and regulations.
