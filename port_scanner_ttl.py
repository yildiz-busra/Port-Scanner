import socket
import sys
import time
from datetime import datetime
import threading
from queue import Queue
import struct

def ttl_os_detection(ip):
    """Detect operating system using TTL value from ICMP response"""
    print(f"\n🧠 TTL-based OS detection for {ip}")

    # First try ICMP (ping)
    try:
        # Create raw socket for ICMP Echo Request (Ping)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(2)  # Increased timeout

        # ICMP header (type, code, checksum, id, sequence number)
        icmp_header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
        icmp_packet = icmp_header
        s.sendto(icmp_packet, (ip, 0))

        start = time.time()
        data, addr = s.recvfrom(1024)
        end = time.time()

        ip_header = data[0:20]
        ttl = struct.unpack('!B', ip_header[8:9])[0]

        print(f"🎯 TTL value: {ttl}")

        # Simple OS predictions based on TTL
        if ttl >= 128:
            return "Windows"
        elif ttl >= 64:
            return "Linux/Unix"
        else:
            return "Unknown"

    except PermissionError:
        print("⛔ Administrator/root privileges required for this operation")
    except socket.timeout:
        print("⏱ No ICMP response received. Trying alternative methods...")
    except Exception as e:
        print("⚠ ICMP Error:", e)
    
    # If ICMP fails, try TCP-based detection
    print("\nTrying TCP-based detection...")
    try:
        # Try common ports that might give us OS information
        test_ports = [80, 443, 22, 445, 3389]
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    # Try to get the service banner
                    banner = get_service_banner(sock)
                    if banner:
                        banner = banner.lower()
                        # Check for Windows-specific signatures
                        if any(x in banner for x in ['windows', 'iis', 'microsoft', 'asp.net']):
                            print("💡 TCP banner suggests: Windows")
                            return "Windows"
                        # Check for Linux/Unix-specific signatures
                        elif any(x in banner for x in ['apache', 'nginx', 'linux', 'ubuntu', 'debian']):
                            print("💡 TCP banner suggests: Linux/Unix")
                            return "Linux/Unix"
                
                # Get TCP window size
                window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                if window_size > 65535:
                    print("💡 TCP window size suggests: Windows")
                    return "Windows"
                elif window_size > 0:
                    print("💡 TCP window size suggests: Linux/Unix")
                    return "Linux/Unix"
                
                sock.close()
            except:
                continue
            finally:
                try:
                    sock.close()
                except:
                    pass
    except Exception as e:
        print("⚠ TCP detection error:", e)
    
    # If all methods fail, try to check if the host is alive using TCP
    print("\nChecking if host is alive...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 80))
        if result == 0:
            print("✅ Host is alive but OS detection failed")
        else:
            print("❌ Host appears to be down or blocking connections")
        sock.close()
    except:
        print("❌ Could not establish connection to host")
    
    return "Detection failed (Host might be blocking ICMP and TCP probes)"

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
    
    # Detect OS using TTL
    os_type = ttl_os_detection(target_ip)
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
        print("Usage: python port_scanner_ttl.py <target> [start_port] [end_port]")
        print("Example: python port_scanner_ttl.py example.com 1 1024")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 65536

    port_scanner(target, start_port, end_port)

if __name__ == "__main__":
    main() 

    