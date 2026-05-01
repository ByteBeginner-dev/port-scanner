import socket
import concurrent.futures
import time
import subprocess
import re

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8000, 8080]
TOP_1000_PORTS = list(range(1, 1001))
ALL_PORTS = list(range(1, 65536))

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None

def run_scanner(ip, ports, max_threads=1000):
    print(f"[*] Starting scan on {ip} with {len(ports)} ports...")

    open_ports = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    duration = time.time() - start_time
    print(f"\n[+] Scan completed in {duration:.2f} seconds.")
    if open_ports:
        print(f"[+] Open ports on {ip}: {sorted(open_ports)}")
        return open_ports
    else:
        print("[-] No open ports found.")
        return []

def run_nmap(ip, open_ports):
    port_str = ','.join(map(str, open_ports))
    print(f"\n[*] Running Nmap for detailed scan on ports: {port_str}")
    try:
        result = subprocess.check_output(['nmap', '-sV', '-p', port_str, ip], stderr=subprocess.STDOUT, text=True)
        print("[+] Nmap scan result:\n")
        print(result)
    except subprocess.CalledProcessError as e:
        print("[!] Error running nmap:")
        print(e.output)

def get_port_list(choice):
    if choice == "1":
        return COMMON_PORTS
    elif choice == "2":
        return TOP_1000_PORTS
    elif choice == "3":
        return ALL_PORTS
    else:
        print("[!] Invalid choice, defaulting to Basic Scan.")
        return COMMON_PORTS

def is_valid_ip(ip):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(pattern, ip) is not None

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ").strip()
    if not is_valid_ip(target_ip):
        print("[!] Invalid IP address format.")
        exit(1)

    print("\nChoose scan type:")
    print("1. Basic Scan (Common Ports)")
    print("2. Top 1000 Ports")
    print("3. Full Scan (1-65535 ports)")
    scan_choice = input("Enter choice (1/2/3): ").strip()

    port_list = get_port_list(scan_choice)
    open_ports = run_scanner(target_ip, port_list)

    if open_ports:
        run_nmap(target_ip, open_ports)
