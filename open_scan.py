import socket
import concurrent.futures
import time

# Define different port sets
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8000 , 8080 ]
TOP_1000_PORTS = list(range(1, 1001))
ALL_PORTS = list(range(1, 65536))

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return None

def run_scanner(ip, ports, max_threads=500):
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
    print(f"[+] Open ports on {ip}:")
    for port in sorted(open_ports):
        print(f" - Port {port} is OPEN")

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

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ").strip()
    print("\nChoose scan type:")
    print("1. Basic Scan (10 common ports)")
    print("2. Top 1000 Ports")
    print("3. Full Scan (1-65535 ports)")
    scan_choice = input("Enter choice (1/2/3): ").strip()

    port_list = get_port_list(scan_choice)
    run_scanner(target_ip, port_list)
