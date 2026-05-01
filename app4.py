import socket
import concurrent.futures
import time
import subprocess
import re
import multiprocessing
import array
import ipaddress
import logging
from functools import partial

# Pre-defined port lists - static allocation
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8000, 8080]
TOP_1000_PORTS = list(range(1, 1001))
ALL_PORTS = list(range(1, 65536))

# Configuration - Can be changed easily
DEFAULT_THREADS_PER_PROCESS = 1000  # Reduced from 8000
DEFAULT_PROCESS_COUNT = 4
SCAN_TIMEOUT = 0.1

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def scan_port(ip, port, timeout=SCAN_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = s.connect_ex((ip, port))
            if result == 0:
                logging.debug(f"Port {port} open on {ip}")
                return port
    except (socket.timeout, socket.error) as e:
        logging.debug(f"Error on port {port}: {e}")
    return None


def scan_chunk(ip, port_chunk, thread_count):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        results = executor.map(partial(scan_port, ip), port_chunk)
        open_ports = [port for port in results if port]
    return open_ports


def static_port_distribution(ports, process_count):
    chunk_size = len(ports) // process_count
    port_chunks = []
    for i in range(process_count):
        start_idx = i * chunk_size
        end_idx = start_idx + chunk_size if i < process_count - 1 else len(ports)
        port_chunks.append(ports[start_idx:end_idx])
    return port_chunks


def run_optimized_scanner(ip, ports, process_count, threads_per_process):
    logging.info(f"Starting scan on {ip} ({len(ports)} ports)")
    logging.info(f"Using {process_count} processes × {threads_per_process} threads")

    start_time = time.time()
    port_chunks = static_port_distribution(ports, process_count)

    with multiprocessing.Pool(process_count) as pool:
        scan_func = partial(scan_chunk, ip)
        results = pool.starmap(
            scan_func, [(chunk, threads_per_process) for chunk in port_chunks]
        )

    open_ports = []
    for sublist in results:
        open_ports.extend(sublist)

    duration = time.time() - start_time
    logging.info(f"Scan completed in {duration:.2f} seconds.")

    if open_ports:
        logging.info(f"Open ports: {sorted(open_ports)}")
    else:
        logging.info("No open ports found.")

    return sorted(open_ports)


def run_nmap(ip, open_ports):
    if not open_ports:
        return

    port_str = ",".join(map(str, open_ports))
    logging.info(f"Running Nmap for detailed scan on: {port_str}")

    try:
        cmd = ["nmap", "-sV", "-p", port_str, ip]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        print("\n[+] Nmap Output:\n")
        print(result)
    except subprocess.CalledProcessError as e:
        logging.error("Nmap failed:")
        print(e.output)


def get_port_list(choice):
    port_lists = {
        "1": COMMON_PORTS,
        "2": TOP_1000_PORTS,
        "3": ALL_PORTS,
    }
    return port_lists.get(choice, COMMON_PORTS)


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    target_ip = input("Enter target IP address: ").strip()
    if not is_valid_ip(target_ip):
        logging.error("Invalid IP address format.")
        exit(1)

    print("\nChoose scan type:")
    print("1. Basic Scan (Common Ports)")
    print("2. Top 1000 Ports")
    print("3. Full Scan (1–65535 Ports)")
    scan_choice = input("Enter choice (1/2/3): ").strip()
    port_list = get_port_list(scan_choice)

    try:
        process_count = int(
            input(f"Number of processes (default: {DEFAULT_PROCESS_COUNT}): ").strip()
        )
    except ValueError:
        process_count = DEFAULT_PROCESS_COUNT
        logging.info(f"Using default process count: {process_count}")

    try:
        threads_per_process = int(
            input(f"Threads per process (default: {DEFAULT_THREADS_PER_PROCESS}): ").strip()
        )
    except ValueError:
        threads_per_process = DEFAULT_THREADS_PER_PROCESS
        logging.info(f"Using default threads per process: {threads_per_process}")

    open_ports = run_optimized_scanner(
        target_ip, port_list, process_count, threads_per_process
    )

    if open_ports:
        run_nmap_choice = input("Run Nmap on open ports? (y/n): ").strip().lower()
        if run_nmap_choice == "y":
            run_nmap(target_ip, open_ports)
