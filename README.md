# Basic WiFi Beacon Frame Analyzer

## Purpose

This script captures and analyzes 802.11 WiFi beacon frames from nearby wireless networks. It displays information such as SSID (network name), BSSID (access point MAC address), channel, signal strength (RSSI), and detected security protocols (Open, WEP, WPA, WPA2/WPA3).

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
5.  The script will then start sniffing for beacon frames and display information about discovered networks.
6.  Press `Ctrl+C` to stop the script.

## Disclaimer

⚠️ **Use responsibly and ethically.** Unauthorized scanning or attempting to access networks without permission is illegal in many jurisdictions. This tool is for passive analysis of publicly broadcast beacon frames only. Ensure you comply with all applicable laws and regulations.
