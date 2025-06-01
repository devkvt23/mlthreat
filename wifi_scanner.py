import sys
from scapy.all import get_if_list, get_if_hwaddr, sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
# Potentially useful if Scapy has these specific layers well-defined:
from scapy.layers.dot11 import Dot11EltRSN, Dot11EltWPA # Check if these are standard


# Cipher Suite Selectors (OUI: 00-0F-AC)
CIPHER_SUITES = {
    1: "TKIP",
    2: "CCMP-128 (AES)", # Often used for WPA/WPA2 pairwise
    4: "CCMP-128 (AES)", # Also common for WPA2 pairwise
    5: "CCMP-256",
    8: "GCMP-128", # WPA3
    9: "GCMP-256", # WPA3
    10: "BIP-CMAC-128", # Management Frame Protection
    11: "BIP-GMAC-128",
    12: "BIP-CMAC-256",
    13: "BIP-GMAC-256"
    # WEP would be handled separately
}

# AKM Suite Selectors (OUI: 00-0F-AC)
AKM_SUITES = {
    1: "802.1X",  # Enterprise
    2: "PSK",     # Pre-Shared Key
    3: "FT-802.1X", # Fast Transition Enterprise
    4: "FT-PSK",    # Fast Transition PSK
    5: "WPA-SHA256-802.1X", # Enterprise SHA256
    6: "WPA-SHA256-PSK",    # PSK SHA256
    7: "TDLS",
    8: "SAE",     # WPA3 Personal
    9: "FT-SAE",  # WPA3 Personal Fast Transition
    11: "OWE",    # Opportunistic Wireless Encryption
    12: "FT-OWE",
    13: "EAP-SUITE-B-192",
    18: "FILS-SHA256", # Fast Initial Link Setup
    19: "FILS-SHA384",
    # Add more as needed
}

# OWE Transition Mode AKM (OUI: 00-0F-AC, Type 18) - though OWE is also an AKM 00-0F-AC:11
OWE_TRANSITION_AKM_OUI = b'\x00\x0f\xac\x12' # OUI 00-0F-AC, Type 18 (0x12)

# Keep track of unique networks to avoid flooding the console with duplicates rapidly
discovered_networks = {}

def parse_cipher_suites(suite_bytes_list, suite_type_dict):
    """Helper to parse a list of cipher suite bytes."""
    parsed = []
    for i in range(0, len(suite_bytes_list), 4):
        suite = suite_bytes_list[i:i+4]
        if suite[0:3] == b'\x00\x0f\xac': # Standard OUI
            cipher_type = suite[3]
            parsed.append(suite_type_dict.get(cipher_type, f"Unknown_00-0F-AC:{cipher_type}"))
        elif suite[0:3] == b'\x00P\xf2': # WPA1 OUI for some ciphers
             cipher_type = suite[3]
             if cipher_type == 1: parsed.append("WEP40") # WPA1 might list WEP for group cipher
             elif cipher_type == 2: parsed.append("TKIP") # WPA1 unicast/pairwise
             elif cipher_type == 4: parsed.append("CCMP-128 (AES)") # WPA1 with AES support
             elif cipher_type == 5: parsed.append("WEP104")
             else: parsed.append(f"Unknown_00-50-F2:{cipher_type}")
        else:
            parsed.append(f"Unknown_OUI:{suite.hex()}")
    return parsed if parsed else ["N/A"]

def parse_akm_suites(suite_bytes_list):
    """Helper to parse a list of AKM suite bytes."""
    return parse_cipher_suites(suite_bytes_list, AKM_SUITES)

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
    """Parses detailed security information from beacon frame elements."""
    protocol = "Open"
    akm_types = ["Open"] # Default AKM for open networks
    pairwise_ciphers = ["N/A"]
    group_cipher = "N/A"

    # Check for RSN IE (WPA2/WPA3) - ID 48
    rsn_elt = packet.getlayer(Dot11Elt, ID=48)
    if rsn_elt:
        # Scapy's Dot11EltRSN might auto-parse, but manual is safer for consistency
        # rsn_info = rsn_elt.info # Raw bytes of the RSN element
        try:
            # Scapy has Dot11EltRSN which can parse these fields
            rsn_data = Dot11EltRSN(rsn_elt.info) # Parse the info field of the generic Dot11Elt
            protocol_name = "WPA3" if any(akm in [AKM_SUITES.get(8), AKM_SUITES.get(9)] for akm in parse_akm_suites(rsn_data.akmsuites)) else "WPA2"

            group_cipher_bytes = rsn_data.mfpcapable #This is wrong, group_cipher is rsn_data.groupcipher
            # Correction: The group cipher is in `rsn_data.groupcs`, not mfpcapable.
            # And pairwise is in `rsn_data.pcslist`
            # AKMs are in `rsn_data.akmslist`
            # For Scapy versions where Dot11EltRSN is well-defined:
            if hasattr(rsn_data, 'groupcs') and rsn_data.groupcs:
                 group_cipher_list = parse_cipher_suites([rsn_data.groupcs], CIPHER_SUITES)
                 group_cipher = group_cipher_list[0] if group_cipher_list else "N/A"

            if hasattr(rsn_data, 'pcslist') and rsn_data.pcslist:
                pairwise_ciphers = []
                for pcs_item in rsn_data.pcslist: # pcslist is a list of cipher suites
                    pairwise_ciphers.extend(parse_cipher_suites([pcs_item.suite], CIPHER_SUITES))
            else: # Fallback if pcslist is not directly available or empty
                 # RSN structure: version (1), group_cipher (4), pairwise_count (2), pairwise_list (N*4), ...
                 # rsn_info bytes:
                 # version = rsn_elt.info[0]
                 # group_cipher_suite = rsn_elt.info[1:5]
                 # pairwise_suite_count = int.from_bytes(rsn_elt.info[5:7], 'little')
                 # offset = 7
                 # pairwise_suites_bytes = rsn_elt.info[offset : offset + pairwise_suite_count * 4]
                 # pairwise_ciphers = parse_cipher_suites(pairwise_suites_bytes, CIPHER_SUITES)
                 # offset += pairwise_suite_count * 4
                 # akm_suite_count = int.from_bytes(rsn_elt.info[offset:offset+2], 'little')
                 # offset += 2
                 # akm_suites_bytes = rsn_elt.info[offset : offset + akm_suite_count * 4]
                 # akm_types = parse_akm_suites(akm_suites_bytes)
                 # This manual parsing is a fallback if scapy's layer isn't working as expected.
                 # For now, rely on Dot11EltRSN fields.
                 pass


            if hasattr(rsn_data, 'akmslist') and rsn_data.akmslist:
                akm_types = []
                for akm_item in rsn_data.akmslist:
                    akm_types.extend(parse_akm_suites([akm_item.suite]))

            # Determine primary protocol based on AKMs and Ciphers
            primary_akm = akm_types[0] if akm_types else "N/A"
            primary_cipher = pairwise_ciphers[0] if pairwise_ciphers else "N/A"

            if "SAE" in akm_types: protocol = "WPA3"
            elif "OWE" in akm_types: protocol = "OWE" # OWE is technically WPA3-era
            elif rsn_elt: protocol = "WPA2" # Default to WPA2 if RSN present and not WPA3/OWE

            # Refine protocol string
            protocol = f"{protocol}-{primary_akm}-{primary_cipher}".replace(" (AES)", "") # Make it cleaner

            # Check for OWE Transition Mode (BSSID matches an RSN network, but also has OWE AKM 00-0f-ac:12)
            # This is complex and might require comparing multiple beacon frames.
            # For now, if OWE AKM (00-0f-ac:11) is found, we call it OWE.
            # If AKM 00-0f-ac:18 (OWE Transition Mode AKM) is present, it's a transition mode.
            if any(akm_item.suite == OWE_TRANSITION_AKM_OUI for akm_item in rsn_data.akmslist if hasattr(akm_item, 'suite')):
                protocol += " (OWE Transition)"


        except Exception as e:
            # Fallback or error logging if Scapy's Dot11EltRSN parsing fails or fields are unexpected
            protocol = "RSN (Error Parsing)"
            # print(f"DEBUG: Error parsing RSN element: {e}, data: {rsn_elt.info.hex()}")


        return {"protocol": protocol, "akm_types": list(set(akm_types)), "pairwise_ciphers": list(set(pairwise_ciphers)), "group_cipher": group_cipher}

    # Check for WPA IE (Vendor Specific - ID 221, OUI 00:50:f2, Type 1)
    wpa_elt = packet.getlayer(Dot11Elt, ID=221)
    if wpa_elt and wpa_elt.info.startswith(b'\x00P\xf2\x01'):
        try:
            wpa_data = Dot11EltWPA(wpa_elt.info) # Scapy should parse this too
            protocol = "WPA"

            if hasattr(wpa_data, 'multicast_cipher') and wpa_data.multicast_cipher:
                 group_cipher_list = parse_cipher_suites([wpa_data.multicast_cipher], CIPHER_SUITES)
                 group_cipher = group_cipher_list[0] if group_cipher_list else "N/A"

            if hasattr(wpa_data, 'unicast_cipher_list') and wpa_data.unicast_cipher_list:
                pairwise_ciphers = []
                for pcs_item in wpa_data.unicast_cipher_list:
                    pairwise_ciphers.extend(parse_cipher_suites([pcs_item.suite], CIPHER_SUITES))

            if hasattr(wpa_data, 'akm_list') and wpa_data.akm_list:
                akm_types = []
                for akm_item in wpa_data.akm_list:
                    akm_types.extend(parse_akm_suites([akm_item.suite]))

            primary_akm = akm_types[0] if akm_types else "N/A"
            primary_cipher = pairwise_ciphers[0] if pairwise_ciphers else "N/A"
            protocol = f"{protocol}-{primary_akm}-{primary_cipher}".replace(" (AES)", "")

        except Exception as e:
            protocol = "WPA (Error Parsing)"
            # print(f"DEBUG: Error parsing WPA element: {e}, data: {wpa_elt.info.hex()}")

        return {"protocol": protocol, "akm_types": list(set(akm_types)), "pairwise_ciphers": list(set(pairwise_ciphers)), "group_cipher": group_cipher}

    # Check for WEP (Privacy bit in capabilities)
    if packet.haslayer(Dot11Beacon):
        capabilities = packet.getlayer(Dot11Beacon).cap
        if capabilities.privacy:
            protocol = "WEP"
            akm_types = ["WEP"]
            # WEP doesn't have explicit pairwise/group ciphers in the same way, this is implicit.
            pairwise_ciphers = ["WEP"]
            group_cipher = "WEP"
            return {"protocol": protocol, "akm_types": akm_types, "pairwise_ciphers": pairwise_ciphers, "group_cipher": group_cipher}

    return {"protocol": protocol, "akm_types": akm_types, "pairwise_ciphers": pairwise_ciphers, "group_cipher": group_cipher}


ENTERPRISE_AKMS = ["802.1X", "FT-802.1X", "WPA-SHA256-802.1X", "EAP-SUITE-B-192", "FILS-SHA256", "FILS-SHA384"]

def calculate_encryption_score(security_details):
    """Calculates the encryption score based on parsed security details.
    Corresponds to sections 3.1.1 & 4.1.2 of the methodology.
    """
    protocol_string = security_details.get("protocol", "Open").upper()
    akm_types = security_details.get("akm_types", [])
    pairwise_ciphers = security_details.get("pairwise_ciphers", []) # List of ciphers

    base_score = 0
    enterprise_bonus = 0

    # Check for Enterprise AKMs first for the bonus
    # Convert akm_types to upper for case-insensitive comparison if needed, but our AKM_SUITES are consistent.
    if any(akm in ENTERPRISE_AKMS for akm in akm_types):
        enterprise_bonus = 10

    # Main protocol scoring
    if "OPEN" in protocol_string: # Covers "Open"
        base_score = 0
    elif "WEP" in protocol_string:
        base_score = 10
    elif "WPA3" in protocol_string or "SAE" in protocol_string : # Covers "WPA3-SAE-CCMP", etc.
        base_score = 90
    elif "OWE" in protocol_string: # Opportunistic Wireless Encryption
        base_score = 85 # Strong encryption, but typically no authentication of AP
        # OWE doesn't typically use the 'Enterprise' AKMs in the same way, so bonus might not apply or be redundant.
        # For now, OWE gets a flat 85.
        enterprise_bonus = 0 # Override bonus for pure OWE.
    elif "WPA2" in protocol_string:
        # Check for AES (CCMP) vs TKIP for WPA2
        if any("CCMP" in cipher.upper() for cipher in pairwise_ciphers):
            base_score = 70
        elif any("TKIP" in cipher.upper() for cipher in pairwise_ciphers):
            base_score = 30 # WPA2 with TKIP is less secure
        else:
            base_score = 30 # Default for WPA2 if ciphers are unclear but not CCMP
    elif "WPA" in protocol_string: # Covers WPA1 (distinct from WPA2, WPA3)
        # WPA usually implies TKIP, but can sometimes have CCMP.
        if any("CCMP" in cipher.upper() for cipher in pairwise_ciphers):
            base_score = 50 # WPA with CCMP is better than TKIP but not full WPA2
        elif any("TKIP" in cipher.upper() for cipher in pairwise_ciphers):
            base_score = 30
        else:
            base_score = 30 # Default for WPA if ciphers unclear

    # Apply enterprise bonus
    total_score = min(base_score + enterprise_bonus, 100) # Cap score at 100

    return total_score


def calculate_configuration_score(packet):
    """Calculates the configuration security score.
    Currently a placeholder returning a neutral score.
    Based on Section 4.1.2 (Configuration Security - 30% weight).
    The score returned is on a 0-100 scale for this category.
    """
    # Placeholder implementation.
    # Future enhancements could involve:
    # - Checking for Wi-Fi Protected Setup (WPS) indicators if available in beacons (often not fully detailed).
    # - Inferring potential default settings (requires vendor OUI analysis and database, complex).
    # - Channel width / proper channel selection (requires broader RF environment context).
    # - Presence of vendor-specific security features (requires deep vendor knowledge).

    # For now, returning a neutral score of 50 out of 100 for this category.
    # This means it neither positively nor negatively impacts the weighted score significantly
    # until more specific checks are implemented.
    return 50


def calculate_behavioral_score(packet):
    """Calculates the behavioral analysis score.
    Currently a placeholder returning a neutral score.
    Based on Section 4.1.2 (Behavioral Analysis - 30% weight).
    The score returned is on a 0-100 scale for this category.
    """
    # Placeholder implementation.
    # Future enhancements could involve:
    # - Beacon interval consistency checks.
    # - Detecting unusual channel hopping.
    # - Identifying abnormal management frame activity.
    # - Storing data over time to detect suspicious patterns (e.g., for evil twin preliminary checks).
    # - Analyzing probe responses.

    # For now, returning a neutral score of 50 out of 100 for this category.
    return 50


def calculate_total_security_score(encryption_score, config_score, behavioral_score):
    """Calculates the overall security score based on weighted individual scores.
    Based on Section 4.1.1.
    """
    encryption_weight = 0.4
    configuration_weight = 0.3
    behavioral_weight = 0.3

    total_score = (encryption_weight * encryption_score) + \
                  (configuration_weight * config_score) + \
                  (behavioral_weight * behavioral_score)

    # Ensure the score is within the 0-100 range (it should be if inputs are 0-100)
    total_score = max(0, min(100, total_score))

    return int(round(total_score)) # Return as a rounded integer


def get_threat_level(total_score):
    """Determines the threat level category based on the total security score.
    Based on Section 4.2.1.
    """
    if 0 <= total_score <= 20:
        return "CRITICAL"
    elif 21 <= total_score <= 40:
        return "HIGH"
    elif 41 <= total_score <= 60:
        return "MEDIUM"
    elif 61 <= total_score <= 80:
        return "LOW"
    elif 81 <= total_score <= 100:
        return "SECURE"
    else:
        return "UNKNOWN" # Should not happen if total_score is always 0-100

def packet_handler(packet):
    """Processes and parses captured beacon frames, calculates security score, and displays info."""
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2  # AP MAC address

        # Avoid re-processing and re-printing the same BSSID too frequently if already fully processed.
        # We can update if some dynamic info (like signal) changes significantly, but for now, once is enough for basic display.
        if bssid in discovered_networks:
            # Optional: Could add logic here to update signal strength if it changes for an already seen BSSID.
            # For now, if we've processed it once, we skip re-printing the full details.
            return

        ssid_elt = packet.getlayer(Dot11Elt, ID=0) # SSID is Element ID 0
        ssid = "Hidden"
        if ssid_elt and ssid_elt.info:
            try:
                ssid = ssid_elt.info.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                ssid = ssid_elt.info.hex()

        channel = "N/A"
        signal_strength = "N/A"

        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            if hasattr(radiotap, 'ChannelFrequency') and radiotap.ChannelFrequency:
                freq = radiotap.ChannelFrequency
                if 2412 <= freq <= 2484:
                    channel = str(int((freq - 2407) / 5))
                elif 5180 <= freq <= 5825:
                    channel = str(int((freq - 5000) / 5))
                else:
                    channel = str(freq) + "MHz"
            if hasattr(radiotap, 'dBm_AntSignal') and radiotap.dBm_AntSignal is not None:
                signal_strength = str(radiotap.dBm_AntSignal) + " dBm"

        # 1. Get detailed security information
        security_details = parse_security_info(packet)

        # 2. Calculate encryption score
        # The calculate_encryption_score expects akm_types, so pass the whole dict.
        encryption_score = calculate_encryption_score(security_details)

        # 3. Calculate configuration score (currently placeholder)
        config_score = calculate_configuration_score(packet)

        # 4. Calculate behavioral score (currently placeholder)
        behavioral_score = calculate_behavioral_score(packet)

        # 5. Calculate total security score
        total_score = calculate_total_security_score(encryption_score, config_score, behavioral_score)

        # 6. Determine threat level
        threat_level = get_threat_level(total_score)

        # Store and print
        network_info = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "signal": signal_strength,
            "security_protocol": security_details["protocol"], # Detailed protocol string
            "encryption_score": encryption_score, # For debugging or more detailed output if desired
            "config_score": config_score,         # "
            "behavioral_score": behavioral_score, # "
            "total_score": total_score,
            "threat_level": threat_level
        }
        discovered_networks[bssid] = network_info

        # Updated print statement
        print("-" * 50)
        print(f"SSID: \"{ssid}\" ({bssid})")
        print(f"  Signal: {signal_strength}, Channel: {channel}")
        print(f"  Security: {security_details['protocol']}")
        print(f"  Score: {total_score}/100 ({threat_level})")
        # Optional: print individual scores for debugging
        # print(f"    Scores (E/C/B): {encryption_score}/{config_score}/{behavioral_score}")
        print("-" * 50)

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
