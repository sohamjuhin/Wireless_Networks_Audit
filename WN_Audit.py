from scapy.all import *

# Function to handle network beacon packets
def handle_beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        channel = ord(pkt[Dot11Elt:3].info)
        print(f"SSID: {ssid} | BSSID: {bssid} | Channel: {channel}")

# Function to perform wireless network audit
def network_audit():
    iface = "wlan0"  # Network interface to use for scanning

    # Set monitor mode on the wireless interface
    os.system(f"ifconfig {iface} down")
    os.system(f"iwconfig {iface} mode monitor")
    os.system(f"ifconfig {iface} up")

    # Start sniffing for beacon frames
    print("Scanning for wireless networks...")
    sniff(iface=iface, prn=handle_beacon, timeout=10)

    # Restore the wireless interface to managed mode
    os.system(f"ifconfig {iface} down")
    os.system(f"iwconfig {iface} mode managed")
    os.system(f"ifconfig {iface} up")

    print("Network audit complete.")

# Main function
def main():
    network_audit()

# Execute the main function
if __name__ == "__main__":
    main()
