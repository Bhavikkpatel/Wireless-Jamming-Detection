# Wi-Fi Deauthentication & Rogue AP Detector

This project implements a simple wireless intrusion detection system using Python, Scapy, and Pandas to detect potential Wi-Fi Deauthentication/Disassociation attacks and Rogue Access Points targeting configured networks.

## Goal

The primary goal is to identify two common Wi-Fi attacks in real-time by analyzing captured 802.11 management frames:

1.  **Deauthentication/Disassociation Floods:** Detect when an excessive number of deauthentication or disassociation frames are sent to clients on the network (or the broadcast address), potentially indicating a jamming or denial-of-service attack.
2.  **Rogue Access Points:** Identify unauthorized Access Points broadcasting the SSID (network name) of a known, legitimate network but originating from an unexpected BSSID (MAC address).

## Features

*   Sniffs 802.11 management frames using Scapy.
*   Detects Deauthentication (subtype 12) and Disassociation (subtype 10) frames.
*   Flags potential deauth attacks based on a configurable frame count threshold within a time window.
*   Detects Beacon frames (subtype 8).
*   Identifies potential Rogue APs by comparing observed SSID/BSSID pairs against a user-defined list of known legitimate networks.
*   Prints real-time alerts to the console upon detection.
*   Logs detected alerts to CSV files (`rogue_ap_alerts.csv`, `deauth_attack_alerts.csv`) using Pandas for later analysis.

## Tech Stack

*   **Python 3:** Core programming language.
*   **Scapy:** Powerful Python library for packet manipulation and sniffing.
*   **Pandas:** Library for data manipulation and analysis, used here for structured logging to CSV.

## Prerequisites

1.  **Python 3:** Ensure Python 3 is installed.
2.  **Pip:** Python package installer (usually comes with Python).
3.  **Wireless Adapter with Monitor Mode Support:** This is **CRITICAL**. Your Wi-Fi card *must* support monitor mode, and you need the ability to enable it. This capability varies significantly by chipset and operating system.
4.  **Root/Administrator Privileges:** Packet sniffing requires elevated permissions (`sudo` on Linux/macOS, running as Administrator on Windows).
5.  **Operating System:**
    *   **Linux:** Generally the easiest platform for Wi-Fi monitor mode and tools like `aircrack-ng`.
    *   **macOS:** Monitor mode is possible but can sometimes be trickier depending on the hardware/OS version.
    *   **Windows:** Monitor mode support is less common and often requires specific drivers (e.g., Npcap installed with Wireshark) and compatible hardware. Full monitor mode functionality might be limited compared to Linux.

## Installation & Setup

1.  **Clone or Download:** Get the `detector_pandas.py` script.
    ```bash
    # If using git
    # git clone <repository_url>
    # cd <repository_directory>
    ```

2.  **Install Dependencies:**
    ```bash
    # pip install scapy pandas
    ```
    *(Use `pip3` if `pip` defaults to Python 2)*

3.  **Enable Monitor Mode on your Wireless Adapter:**
    This process varies by OS and adapter. **You must do this before running the script.**
    *   **Linux (Example using `airmon-ng` from `aircrack-ng` suite):**
        ```bash
        # Replace wlan0 with your actual wireless interface
        sudo airmon-ng check kill    # Stop potentially interfering processes
        sudo airmon-ng start wlan0
        # Note the name of the new monitor interface (e.g., wlan0mon)
        ```
    *   **Linux (Example using `ip`/`iw`):**
        ```bash
        # Replace wlan0 with your actual wireless interface
        sudo ip link set wlan0 down
        sudo iw dev wlan0 set type monitor
        sudo ip link set wlan0 up
        # Verify with: iwconfig wlan0 (Should show Mode:Monitor)
        # Use wlan0 as the interface name in this case
        ```
    *   **Windows/macOS:** Research the specific method for your hardware, drivers, and OS (e.g., using Npcap/Wireshark drivers on Windows, `airport` command on macOS).

## Configuration

Edit the `detector.py` script directly to configure these settings:

1.  **`KNOWN_APS` Dictionary:**
    *   **Purpose:** Defines your legitimate Wi-Fi networks for Rogue AP detection.
    *   **Format:** A Python dictionary where keys are SSIDs (network names, case-sensitive strings) and values are their corresponding legitimate BSSIDs (AP MAC addresses, lowercase strings).
    *   **How to find details:**
        *   **Linux:** Use `iw dev <iface> link`, `nmcli dev wifi list`, or `iwconfig <iface>`.
        *   **Windows:** Use `netsh wlan show interfaces`.
        *   **macOS:** Use `airport -I`.
    *   **Example:**
        ```python
        KNOWN_APS = {
            "MyHomeNetwork": "aa:bb:cc:dd:ee:ff",
            "OfficeWiFi": "11:22:33:44:55:66",
        }
        ```

2.  **Deauthentication Detection Settings:**
    *   `DEAUTH_THRESHOLD = 5`: Number of deauth/disassoc frames from a source to a destination needed to trigger an alert.
    *   `DEAUTH_TIME_WINDOW = 10`: The time window (in seconds) within which the threshold must be met.

## Usage

1.  **Ensure Monitor Mode is Active** on your chosen wireless interface.
2.  **Open a terminal or command prompt with Root/Administrator privileges.**
3.  **Navigate** to the directory containing `detector_pandas.py`.
4.  **Run the script:** Replace `<monitor_interface_name>` with the actual name of your interface in monitor mode (e.g., `wlan0mon`, `mon0`, or the name identified during setup).

    ```bash
    sudo python3 detector.py --interface <monitor_interface_name>
    ```
    *Optional arguments:*
    *   `--rogue-log <filename>`: Specify a different filename for the rogue AP log (default: `rogue_ap_alerts.csv`).
    *   `--deauth-log <filename>`: Specify a different filename for the deauth attack log (default: `deauth_attack_alerts.csv`).

5.  **Monitor the Output:** The script will print alerts to the console when potential attacks are detected.
6.  **Stop the Script:** Press `Ctrl+C`. Upon stopping, the script will save any logged alerts to the specified CSV files.

## Testing

To verify the script is working, you can simulate attacks ( **Only test on networks you own or have explicit permission to test!** ):

*   **Deauthentication Attack:** Use a separate device with tools like `aireplay-ng` (part of `aircrack-ng`) to send deauth packets targeting your network's BSSID or a specific client MAC connected to it.
    ```bash
    # Example targeting broadcast (replace BSSID and monitor interface)
    sudo aireplay-ng --deauth 20 -a AA:BB:CC:DD:EE:FF wlanXmon
    ```
*   **Rogue Access Point:** Use a separate device (or software like `airbase-ng`, `hostapd`, or even a mobile phone hotspot) to create a Wi-Fi network broadcasting the *same SSID* as one listed in your `KNOWN_APS`, but originating from a *different MAC address* (BSSID).

## Output / Logging

*   **Console:** Real-time alerts are printed with timestamps and relevant details (SSID, BSSIDs, client/source MACs, counts).
*   **CSV Files:**
    *   `rogue_ap_alerts.csv`: Logs detected potential rogue APs. Columns: `Timestamp`, `SSID`, `Detected_BSSID`, `Known_BSSID`.
    *   `deauth_attack_alerts.csv`: Logs detected potential deauthentication attacks. Columns: `Timestamp`, `Target_Client`, `Source`, `Count`, `Window_Sec`, `Is_Broadcast`.
    These files are created/updated in the script's running directory when you stop the script (`Ctrl+C`) if any alerts were triggered during the session.

## Limitations

*   **Monitor Mode Dependency:** Relies heavily on the proper functioning of monitor mode, which can be hardware and OS-dependent.
*   **Single Channel:** By default, Scapy sniffs on the channel the monitor interface is currently set to. Attackers might operate on different channels. Implementing channel hopping adds complexity.
*   **Basic Detection Logic:** Threshold-based detection can lead to false positives (on noisy networks) or false negatives (for slow attacks).
*   **Performance:** Python/Scapy might drop packets on very high-traffic networks.
*   **No Decryption:** Only analyzes unencrypted management frames.
*   **Spoofing:** Attackers can spoof source MAC addresses, potentially complicating analysis, though flood detection remains useful.

## Potential Improvements

*   Implement channel hopping to monitor multiple channels.
*   Develop more sophisticated detection algorithms (e.g., rate analysis, state tracking).
*   Use a configuration file (e.g., YAML, JSON) instead of hardcoding `KNOWN_APS`.
*   Add detection based on AP security configuration mismatches (e.g., known WPA2 network suddenly advertised as Open by a rogue AP).
*   Integrate with notification systems (e.g., email, Slack).
*   Develop a simple GUI.

## Disclaimer

This script is intended for educational purposes and network monitoring **on networks you own or have explicit permission to test.** Unauthorized scanning or testing on networks is illegal and unethical. The author(s) are not responsible for any misuse of this script. Always ensure you comply with local laws and regulations.
