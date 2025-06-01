import sys
from scapy.all import get_if_list, get_if_hwaddr, sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap

# Keep track of unique networks to avoid flooding the console with duplicates rapidly
discovered_networks = {}

def list_interfaces():
    """Lists available network interfaces."""
    print("Available network interfaces:")
    ifaces = get_if_list()
    for iface_name in ifaces:
        try:
            hw_addr = get_if_hwaddr(iface_name)
            print(f"  - {iface_name} (MAC: {hw_addr})")
        except:
            print(f"  - {iface_name}")

    if not ifaces:
        print("No interfaces found. Ensure you have appropriate permissions and drivers.")
        sys.exit(1)
    return ifaces

def parse_security_info(packet):
    """Parses security information from beacon frame elements."""
    sec_info = {"protocol": "Open", "pairwise_cipher": [], "group_cipher": ""}

    # Check for RSN IE (WPA2/WPA3)
    rsn_info = packet.getlayer(Dot11Elt, ID=48) # ID 48 for RSN
    if rsn_info:
        # RSN Version 1 is typical
        # pairwise_cipher_suites and group_cipher_suite tell us about encryption
        # For simplicity, we'll just mark as RSN (WPA2/WPA3)
        # A deeper parse could look at AKM suites to differentiate WPA2-PSK, WPA3-SAE etc.
        sec_info["protocol"] = "WPA2/WPA3 (RSN)"
        # Example of trying to get more details (can be complex)
        # try:
        #     # RSNElement class from scapy.layers.dot11 provides parsed fields
        #     # but direct access to bytes and manual parsing might be needed for full detail
        #     # For now, this is a placeholder for more detailed parsing
        #     # Count of pairwise_cipher_suites
        #     # Pairwise_cipher_suite_list
        #     # Group_cipher_suite
        #     # AKM_suite_count
        #     # AKM_suite_list
        # except Exception as e:
        #     print(f"DEBUG: Could not parse RSN details: {e}")
        return sec_info

    # Check for WPA IE (Vendor Specific)
    wpa_info = packet.getlayer(Dot11Elt, ID=221) # ID 221 for Vendor Specific
    if wpa_info and wpa_info.info.startswith(b'\x00P\xf2\x01'): # OUI 00:50:f2 and Type 1 for WPA
        sec_info["protocol"] = "WPA"
        return sec_info

    # Check for WEP (Privacy bit in capabilities)
    # Dot11Beacon layer has a 'cap' field for capabilities
    if packet.haslayer(Dot11Beacon):
        capabilities = packet.getlayer(Dot11Beacon).cap
        if capabilities.privacy: # Check if the privacy bit is set
            # If privacy bit is set and no WPA/RSN IE found, it's likely WEP
            sec_info["protocol"] = "WEP"
            return sec_info

    return sec_info


def packet_handler(packet):
    """Processes and parses captured beacon frames."""
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2  # AP MAC address

        # Avoid processing the same BSSID too frequently if already printed
        if bssid in discovered_networks:
            return

        ssid_elt = packet.getlayer(Dot11Elt, ID=0) # SSID is Element ID 0
        ssid = "Hidden" # Default for hidden SSIDs
        if ssid_elt and ssid_elt.info:
            try:
                ssid = ssid_elt.info.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                ssid = ssid_elt.info.hex() # Fallback to hex if decode fails

        channel = "N/A"
        signal_strength = "N/A"

        # Try to get channel and signal strength from RadioTap header if present
        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            # Channel frequency can be in RadioTap
            if hasattr(radiotap, 'ChannelFrequency') and radiotap.ChannelFrequency:
                # Basic conversion from frequency to channel number (for 2.4 GHz and 5 GHz)
                freq = radiotap.ChannelFrequency
                if 2412 <= freq <= 2484: # 2.4 GHz band
                    channel = str(int((freq - 2407) / 5))
                elif 5180 <= freq <= 5825: # 5 GHz band
                    channel = str(int((freq - 5000) / 5))
                else:
                    channel = str(freq) + "MHz"

            # Signal strength
            if hasattr(radiotap, 'dBm_AntSignal') and radiotap.dBm_AntSignal is not None:
                signal_strength = str(radiotap.dBm_AntSignal) + " dBm"

        security = parse_security_info(packet)

        # Store and print
        network_info = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "signal": signal_strength,
            "security": security['protocol']
        }
        discovered_networks[bssid] = network_info # Add to discovered list

        print(f"SSID: \"{ssid}\" ({bssid}) - Channel: {channel} - Signal: {signal_strength} - Security: {security['protocol']}")


def start_sniffing(interface_name):
    """Starts sniffing for beacon frames on the specified interface."""
    print(f"\nStarting to sniff for beacon frames on interface: {interface_name}")
    print("Press Ctrl+C to stop sniffing.")
    try:
        sniff(iface=interface_name, prn=packet_handler, lfilter=lambda p: p.haslayer(Dot11Beacon), store=0)
    except PermissionError:
        print(f"Error: Permission denied for sniffing on {interface_name}. Try running as root/administrator.")
        sys.exit(1)
    except OSError as e:
        if "No such device" in str(e) or "Network is down" in str(e):
             print(f"Error: Interface {interface_name} not found or not up. Please ensure it's correctly configured and in monitor mode.")
        else:
            print(f"An OS error occurred during sniffing: {e}")
        sys.exit(1)
    except KeyboardInterrupt: # Catch Ctrl+C
        print("\nSniffing stopped by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred during sniffing: {e}")
        sys.exit(1)

def main():
    print("WiFi Beacon Frame Analyzer")
    print("=" * 30)

    available_interfaces = list_interfaces()

    print("\n" + "=" * 30)
    print("IMPORTANT: Before proceeding, you MUST ensure the wireless interface")
    print("you intend to use is in MONITOR MODE.")
    # ... (OS-specific instructions)
    print("  - Linux: Generally `sudo ip link set [interface_name] down && sudo iwconfig [interface_name] mode monitor && sudo ip link set [interface_name] up`")
    print("  - macOS: `sudo airport [interface_name] sniff [channel]` (creates a new interface like mon0)")
    print("  - Windows: Requires specialized drivers and tools like Npcap for monitor mode with Wireshark/Scapy.")
    print("Please consult documentation for your specific OS and WiFi adapter.")
    print("=" * 30)

    selected_interface = None
    while not selected_interface:
        iface_input = input("Enter the name of the wireless interface in monitor mode: ").strip()
        if iface_input in available_interfaces:
            selected_interface = iface_input
        else:
            print(f"Error: Interface '{iface_input}' not in the list of available interfaces or invalid. Please try again.")
            print("Available interfaces are:", ", ".join(available_interfaces))

    start_sniffing(selected_interface)

if __name__ == "__main__":
    main()
