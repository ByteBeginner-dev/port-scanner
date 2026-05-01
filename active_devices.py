from scapy.all import ARP, Ether, srp
import netifaces as ni

def get_default_interface_network():
    gateway = ni.gateways()['default'][ni.AF_INET][1]
    ip_info = ni.ifaddresses(gateway)[ni.AF_INET][0]
    ip = ip_info['addr']
    netmask = ip_info['netmask']

    # Calculate CIDR notation
    cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
    return f"{ip}/{cidr}"

def arp_scan():
    network = get_default_interface_network()
    print(f"[+] Scanning network: {network}")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Active devices found:")
    print("IP\t\tMAC")
    print("-" * 30)
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

if __name__ == "__main__":
    arp_scan()
