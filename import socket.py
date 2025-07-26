import socket
import threading

open_ports = []  # Global list to store open ports

def scan_port(ip, port):
    """
    Scan a single TCP port on the given IP address.
    If open, prints and stores it.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                print(f"[OPEN] Port {port} ({service})")
                open_ports.append(port)
    except Exception as e:
        pass  # Silently ignore unreachable ports

def start_scan(ip, start_port, end_port):
    """
    Scans a range of ports on the target IP using multi-threading.
    """
    print(f"\n[INFO] Scanning {ip} from port {start_port} to {end_port}...\n")
    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if open_ports:
        print(f"\n[INFO] Scan completed. {len(open_ports)} open port(s) found.")
    else:
        print("\n[INFO] No open ports found in the given range.")

def main():
    """
    Main program logic for user interaction and input validation.
    """
    try:
        target = input("Enter IP address or domain to scan: ").strip()
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            print("[ERROR] Unable to resolve host.")
            return

        start_port = int(input("Enter starting port (0-65535): "))
        end_port = int(input("Enter ending port (>= start port): "))

        if start_port < 0 or end_port > 65535 or start_port > end_port:
            print("[ERROR] Invalid port range.")
            return

        start_scan(ip, start_port, end_port)

    except ValueError:
        print("[ERROR] Please enter valid numbers for ports.")
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")

if __name__ == "__main__":
    main()
