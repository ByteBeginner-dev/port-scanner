import socket
import concurrent.futures
import time
import subprocess
import re
import multiprocessing
import array
from functools import partial

# Pre-defined port lists - static allocation
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8000, 8080]
TOP_1000_PORTS = list(range(1, 1001))
ALL_PORTS = list(range(1, 65536))

# Configuration - Can be changed easily
DEFAULT_THREADS_PER_PROCESS =8000
DEFAULT_PROCESS_COUNT = 8
SCAN_TIMEOUT = 0.1


def create_result_arrays(process_count, chunk_size):
    # Static allocation of result arrays for each process
    return [array.array('i', [0] * chunk_size) for _ in range(process_count)]


def scan_port(ip, port, timeout=SCAN_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = s.connect_ex((ip, port))
            if port > 1000 and result == 0:  # Debug high ports
                print(f"[DEBUG] High port {port} found open")
            return port if result == 0 else None
    except (socket.timeout, socket.error) as e:
        if port > 1000:  # Debug high ports
            print(f"[DEBUG] Error scanning port {port}: {str(e)}")
        return None


def scan_chunk(ip, port_chunk, thread_count):
    # Static allocation of ThreadPoolExecutor with fixed size
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        # Use map for better memory management
        results = executor.map(partial(scan_port, ip), port_chunk)
        for port in results:
            if port:
                open_ports.append(port)
    return open_ports


def static_port_distribution(ports, process_count):
    # Static division of ports among processes
    chunk_size = len(ports) // process_count
    port_chunks = []

    # Precompute all chunks instead of using generators
    for i in range(process_count):
        start_idx = i * chunk_size
        end_idx = start_idx + chunk_size if i < process_count - 1 else len(ports)
        port_chunks.append(ports[start_idx:end_idx])

    return port_chunks


def run_optimized_scanner(ip, ports, process_count, threads_per_process):
    print(f"[*] Starting scan on {ip} with {len(ports)} ports...")
    print(
        f"[*] Using {process_count} processes with {threads_per_process} threads each"
    )

    start_time = time.time()

    # Precompute port chunks statically
    port_chunks = static_port_distribution(ports, process_count)

    # Static allocation of Process Pool
    with multiprocessing.Pool(processes=process_count) as pool:
        # Use static partial function for better memory efficiency
        scan_func = partial(scan_chunk, ip)
        results = pool.starmap(
            scan_func, [(chunk, threads_per_process) for chunk in port_chunks]
        )

    # Pre-allocate the result list with estimated size
    max_ports = len(ports)
    open_ports = []

    # Flatten results - more efficient than list comprehension
    for sublist in results:
        open_ports.extend(sublist)

    duration = time.time() - start_time
    print(f"\n[+] Scan completed in {duration:.2f} seconds.")

    if open_ports:
        print(f"[+] Open ports on {ip}: {sorted(open_ports)}")
        return sorted(open_ports)
    else:
        print("[-] No open ports found.")
        return []


def run_nmap(ip, open_ports):
    if not open_ports:
        return

    # Convert ports to string once
    port_str = ",".join(map(str, open_ports))
    print(f"\n[*] Running Nmap for detailed scan on ports: {port_str}")

    try:
        # Pre-allocate command list
        cmd = ["nmap", "-sV", "-p", port_str, ip]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        print("[+] Nmap scan result:\n")
        print(result)
    except subprocess.CalledProcessError as e:
        print("[!] Error running nmap:")
        print(e.output)


def get_port_list(choice):
    # Direct static references instead of conditionals
    port_lists = {
        "1": COMMON_PORTS,
        "2": TOP_1000_PORTS,
        "3": ALL_PORTS,
    }
    return port_lists.get(choice, COMMON_PORTS)


def is_valid_ip(ip):
    # Pre-compile the regex pattern
    pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return bool(pattern.match(ip))


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

    # Get process and thread counts from user, or use defaults
    try:
        process_count = int(
            input(
                f"Enter number of processes (default: {DEFAULT_PROCESS_COUNT}): "
            ).strip()
        )
    except ValueError:
        process_count = DEFAULT_PROCESS_COUNT
        print(f"Using default process count: {process_count}")

    try:
        threads_per_process = int(
            input(
                f"Enter number of threads per process (default: {DEFAULT_THREADS_PER_PROCESS}): "
            ).strip()
        )
    except ValueError:
        threads_per_process = DEFAULT_THREADS_PER_PROCESS
        print(f"Using default threads per process: {threads_per_process}")

    open_ports = run_optimized_scanner(
        target_ip, port_list, process_count, threads_per_process
    )

    if open_ports:
        run_nmap_choice = (
            input("\nRun Nmap on open ports? (y/n): ").strip().lower()
        )
        if run_nmap_choice == "y":
            run_nmap(target_ip, open_ports)

