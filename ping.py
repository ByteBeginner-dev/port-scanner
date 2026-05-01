from scapy.all import IP, TCP, sr1

def syn_ping(ip, ports=[80, 135, 139, 445, 3389], timeout=1):
    print(f"[*] Sending SYN packets to {ip} on common ports...")

    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=timeout, verbose=0)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                print(f"[+] {ip} responded on port {port} (SYN-ACK)")
                print(f"✅ Host {ip} is ONLINE")
                return True
            elif response[TCP].flags == 0x14:  # RST-ACK
                print(f"[-] {ip} responded with RST on port {port}")
                print(f"✅ Host {ip} is ONLINE")
                return True

    print(f"[!] No SYN responses from {ip}")
    print(f"❌ Host {ip} is OFFLINE or fully filtered")
    return False

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ").strip()
    syn_ping(target_ip)
