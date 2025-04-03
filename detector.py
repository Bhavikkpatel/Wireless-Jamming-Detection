# To run in Linux
# 1. create my_rogues.csv and my_deauths.csv
# 2. create virtual environment python -m venv venv
# 3. source venv/bin/activate
# 4. pip install scapy pandas
# 5. run netsh wlan show interfaces to get SSID and AP BSSID
# 6. sudo python3 detector_pandas.py --interface wlan0mon --rogue-log my_rogues.csv --deauth-log my_deauths.csv

import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disassoc, Dot11Elt
import time
import argparse
from collections import defaultdict
import os
import sys
import pandas as pd

# --- Configuration ---

# Dictionary to store known legitimate APs {ssid: bssid}
KNOWN_APS = {
    "Velloremates_5G": "8c:c7:c3:54:34:eb"
}

# Deauthentication detection settings
DEAUTH_THRESHOLD = 5 
DEAUTH_TIME_WINDOW = 10

deauth_tracker = defaultdict(list)
observed_aps = defaultdict(set)
alerted_rogues = set()
alerted_deauths = set()

# Pandas DataFrames for Logging Alerts 
rogue_log = pd.DataFrame(columns=['Timestamp', 'SSID', 'Detected_BSSID', 'Known_BSSID'])
deauth_log = pd.DataFrame(columns=['Timestamp', 'Target_Client', 'Source', 'Count', 'Window_Sec', 'Is_Broadcast'])

def get_ssid_and_bssid(beacon_frame):
    if not beacon_frame.haslayer(Dot11Elt):
        return None, None
    bssid = beacon_frame.addr2
    ssid = None
    elt = beacon_frame.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0 and elt.len > 0:
            try:
                ssid = elt.info.decode('utf-8', errors='ignore')
                break
            except Exception:
                pass
        elt = elt.payload.getlayer(Dot11Elt)
        
    return ssid, bssid

def check_rogue_ap(ssid, bssid):
    global rogue_log
    if not ssid or not bssid:
        return
    bssid_lower = bssid.lower()
    observed_aps[ssid].add(bssid_lower)
    if ssid in KNOWN_APS:
        known_bssid_lower = KNOWN_APS[ssid].lower()
        if bssid_lower != known_bssid_lower:
            rogue_key = (ssid, bssid_lower)
            if rogue_key not in alerted_rogues:
                timestamp = pd.Timestamp.now()
                print(f"[{timestamp}] ALERT: Potential Rogue AP Detected!")
                print(f"    SSID: {ssid}")
                print(f"    Detected BSSID: {bssid_lower}")
                print(f"    Known Legitimate BSSID: {known_bssid_lower}")
                print("-" * 30)
                alerted_rogues.add(rogue_key)

                # Log to Pandas DataFrame
                new_rogue_entry = pd.DataFrame([{
                    'Timestamp': timestamp,
                    'SSID': ssid,
                    'Detected_BSSID': bssid_lower,
                    'Known_BSSID': known_bssid_lower
                }])
                rogue_log = pd.concat([rogue_log, new_rogue_entry], ignore_index=True)

def check_deauth_attack(pkt):
    global deauth_log
    if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disassoc)):
        return
    client_mac = pkt.addr1
    source_mac = pkt.addr2
    is_broadcast = client_mac == "ff:ff:ff:ff:ff:ff"
    
    # Use a key combining source and destination for tracking
    target_key = f"{source_mac}_to_{client_mac}" 

    current_time = time.time()
    deauth_tracker[target_key].append(current_time)

    deauth_tracker[target_key] = [ts for ts in deauth_tracker[target_key] if current_time - ts <= DEAUTH_TIME_WINDOW]
    
    count = len(deauth_tracker[target_key])
    if count >= DEAUTH_THRESHOLD:
        if target_key not in alerted_deauths:
            timestamp = pd.Timestamp.now()
            attack_type = "BROADCAST " if is_broadcast else ""
            print(f"[{timestamp}] ALERT: Potential {attack_type}Deauthentication/Disassociation Attack Detected!")
            print(f"    Target (addr1): {client_mac}")
            print(f"    Source (addr2): {source_mac}")
            print(f"    Count:          {count} frames in last {DEAUTH_TIME_WINDOW} seconds")
            print("-" * 30)
            alerted_deauths.add(target_key)

            # Log to Pandas DataFrame
            new_deauth_entry = pd.DataFrame([{
                'Timestamp': timestamp,
                'Target_Client': client_mac,
                'Source': source_mac,
                'Count': count,
                'Window_Sec': DEAUTH_TIME_WINDOW,
                'Is_Broadcast': is_broadcast
            }])
            deauth_log = pd.concat([deauth_log, new_deauth_entry], ignore_index=True)

def packet_handler(pkt):
    # 802.11 Management Frames (type=0)
    if pkt.haslayer(Dot11) and pkt.type == 0:
        # Beacon frames (subtype=8) for Rogue AP detection
        if pkt.subtype == 8: # Beacon frame
           ssid, bssid = get_ssid_and_bssid(pkt)
           if ssid and bssid:
               check_rogue_ap(ssid, bssid)
        # Deauthentication (subtype=12) or Disassociation (subtype=10) frames
        elif pkt.subtype == 12 or pkt.subtype == 10:
            check_deauth_attack(pkt)

if __name__ == "__main__":
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[-] This script requires root/administrator privileges for packet sniffing.")
        print("[-] Please run with sudo (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Wi-Fi Deauthentication and Rogue AP Detector with Pandas Logging")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface name in monitor mode (e.g., wlan0mon)")
    parser.add_argument("--rogue-log", default="rogue_ap_alerts.csv", help="Filename for rogue AP alert CSV log (default: rogue_ap_alerts.csv)")
    parser.add_argument("--deauth-log", default="deauth_attack_alerts.csv", help="Filename for deauth attack alert CSV log (default: deauth_attack_alerts.csv)")
    args = parser.parse_args()

    iface = args.interface
    rogue_log_file = args.rogue_log
    deauth_log_file = args.deauth_log

    print("[*] Starting Wi-Fi Detector...")
    print(f"[*] Monitoring on interface: {iface}")
    print(f"[*] Known Legitimate APs:")
    if KNOWN_APS:
        for ssid, bssid in KNOWN_APS.items():
            print(f"    - SSID: \"{ssid}\", BSSID: {bssid.lower()}")
    else:
        print("    (None configured - Rogue AP detection for specific SSIDs disabled)")
    print(f"[*] Deauth Attack Threshold: {DEAUTH_THRESHOLD} frames / {DEAUTH_TIME_WINDOW} seconds")
    print(f"[*] Rogue AP alerts will be logged to: {rogue_log_file}")
    print(f"[*] Deauth attack alerts will be logged to: {deauth_log_file}")
    print("[*] Ensure your interface is in MONITOR MODE.")
    print("[*] Press Ctrl+C to stop.")
    print("-" * 30)
    if sys.platform.startswith('linux'):
        try:
            iwconfig_out = os.popen(f'iwconfig {iface}').read()
            if 'Mode:Monitor' not in iwconfig_out:
                 print(f"[!] Warning: Interface {iface} might not be in monitor mode.")
                 print(f"    Current 'iwconfig {iface}' output snippet:")
                 print(f"    {iwconfig_out.strip().splitlines()[0]}") # Print first line only
                 print(f"    Please ensure it's set correctly (e.g., using airmon-ng start {iface} or iw commands).")
        except Exception as e:
             print(f"[!] Could not check interface mode via iwconfig: {e}")
    else:
        print("[!] Monitor mode check skipped (iwconfig not available on this platform).")
        print("[!] Please manually verify that the interface is in monitor mode.")

    try:
        scapy.sniff(iface=iface, prn=packet_handler, store=0)
        
    except OSError as e:
         if "No such device" in str(e) or "Network is down" in str(e):
              print(f"\n[-] Error: Interface '{iface}' not found or not up.")
              print("[-] Please verify the interface name and ensure it's active and in monitor mode.")
         else:
              print(f"\n[-] An OS error occurred during sniffing: {e}")
         sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred during sniffing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[*] Stopping detector...")
        try:
            if not rogue_log.empty:
                rogue_log.to_csv(rogue_log_file, index=False)
                print(f"[*] Rogue AP alerts saved to {rogue_log_file}")
            else:
                print(f"[*] No rogue AP alerts were logged.")

            if not deauth_log.empty:
                deauth_log.to_csv(deauth_log_file, index=False)
                print(f"[*] Deauth attack alerts saved to {deauth_log_file}")
            else:
                 print(f"[*] No deauthentication attack alerts were logged.")
        except Exception as e:
            print(f"\n[-] Error saving log files: {e}")
        print(f"[*] Remember to potentially set '{iface}' back to managed mode if needed.")
        print("[*] Exiting.")