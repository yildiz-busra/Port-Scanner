import socket
import sys
import time
from datetime import datetime
import threading
from queue import Queue
import struct
import random

def get_ip_from_domain(domain):
    """Convert domain name to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print("Error: Could not resolve hostname")
        sys.exit(1)

def get_service_banner(sock):
    """Attempt to get service banner from the socket"""
    try:
        # Set a short timeout for receiving the banner
        sock.settimeout(2)
        # Try to receive up to 1024 bytes
        banner = sock.recv(1024)
        if banner:
            # Decode and clean the banner
            return banner.decode('utf-8', errors='ignore').strip()
    except:
        pass
    return None

def scan_port(target, port, open_ports):
    """Scan a single port and identify the service"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            # Try to get the service banner
            banner = get_service_banner(sock)
            if banner:
                service_info = f"Service: {banner}"
            else:
                # If no banner, try to get service name from socket
                try:
                    service = socket.getservbyport(port)
                    service_info = f"Service: {service}"
                except:
                    service_info = "Service: Unknown"
            open_ports.append((port, service_info))
        sock.close()
    except:
        pass

def detect_os(target):
    """Detect operating system using TCP/IP stack behavior analysis"""
    try:
        # Try to connect to common ports and analyze responses
        os_signatures = {
            'Windows': {
                'ttl': 128,
                'window_size': 65535,
                'flags': 0x02
            },
            'Linux/Unix': {
                'ttl': 64,
                'window_size': 5840,
                'flags': 0x02
            }
        }
        
        # Try multiple ports for better accuracy
        test_ports = [80, 443, 22]
        responses = []
        
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Get the service banner if available
                    banner = get_service_banner(sock)
                    if banner:
                        responses.append(banner.lower())
                sock.close()
            except:
                continue
        
        # Analyze responses for OS signatures
        if responses:
            # Check for Windows-specific signatures
            windows_sigs = ['windows', 'iis', 'microsoft', 'asp.net']
            linux_sigs = ['apache', 'nginx', 'linux', 'ubuntu', 'debian', 'centos']
            
            for response in responses:
                for sig in windows_sigs:
                    if sig in response:
                        return "Windows"
                for sig in linux_sigs:
                    if sig in response:
                        return "Linux/Unix"
        
        # If no clear signature found, try TCP/IP stack behavior
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, 80))
        
        # Get socket options
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        
        # Compare with known signatures
        for os_name, sig in os_signatures.items():
            if abs(ttl - sig['ttl']) <= 10:  # Allow some margin of error
                return os_name
        
        return "Unknown OS (Could not determine with certainty)"
            
    except Exception as e:
        return "Detection failed (Try running with administrator privileges)"
    finally:
        try:
            sock.close()
        except:
            pass

def port_scanner(target, start_port=1, end_port=1024):
    """Main port scanning function"""
    # Convert domain to IP if necessary
    try:
        target_ip = socket.inet_aton(target)
        target_ip = target
    except socket.error:
        target_ip = get_ip_from_domain(target)

    print(f"\nStarting port scan for {target} ({target_ip})")
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    
    # Detect OS
    print("Detecting operating system...")
    os_type = detect_os(target_ip)
    print(f"Detected OS: {os_type}")
    print("-" * 50)

    open_ports = []
    threads = []
    q = Queue()

    # Create thread pool
    for port in range(start_port, end_port + 1):
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            scan_port(target_ip, port, open_ports)
            q.task_done()

    # Start threads
    for _ in range(100):  # Limit to 100 concurrent threads
        t = threading.Thread(target=worker)
        t.daemon = True
        threads.append(t)
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Print results
    if open_ports:
        print("\nOpen ports and services:")
        print("-" * 50)
        for port, service in sorted(open_ports):
            print(f"Port {port}: {service}")
    else:
        print("\nNo open ports found in the specified range.")

    print(f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target> [start_port] [end_port]")
        print("Example: python port_scanner.py example.com 1 1024")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 65536

    port_scanner(target, start_port, end_port)

if __name__ == "__main__":
    main() 