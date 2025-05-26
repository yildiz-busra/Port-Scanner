import socket
import sys
import time
from datetime import datetime
import threading
from queue import Queue

def classify_os(ttl, window_size, tcp_options=None):
    """
    OS classification based on TTL, window size and TCP options
    ttl: int - IP TTL from the response
    window_size: int - TCP window size
    tcp_options: list of str - e.g., ['MSS', 'SACK', 'TS', 'WS']
    """
    # Normalize TTL if needed
    if ttl >= 128:
        ttl_class = "high"
    elif ttl >= 64:
        ttl_class = "medium"
    else:
        ttl_class = "low"

    # Windows fingerprints
    if ttl_class == "high":
        if window_size in (64240, 8192, 65535):
            return "Windows (likely)"
        elif window_size > 65535:
            return "Windows (likely)"
        else:
            return "Windows or unknown"
    
    # Linux/Unix fingerprints
    elif ttl_class == "medium":
        if window_size in (5840, 29200, 14600, 65535):
            if tcp_options:
                if "TS" in tcp_options and "WS" in tcp_options:
                    return "Linux/Unix (likely)"
                elif "MSS" in tcp_options and "SACK" in tcp_options:
                    return "macOS or Linux"
            return "Linux/Unix (maybe)"
        elif 16384 <= window_size <= 65535:
            return "Linux/Unix (likely)"
    
    # Network devices and unusual configurations
    elif ttl_class == "low":
        if window_size in (4128, 16384):
            return "Cisco or network device"
        else:
            return "Unusual config or embedded OS"

    return "OS Unknown"

def get_tcp_options(sock):
    """Get TCP options from socket"""
    options = []
    try:
        # Check for MSS
        mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        if mss > 0:
            options.append("MSS")
        
        # Check for window scaling
        try:
            ws = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP)
            if ws > 0:
                options.append("WS")
        except:
            pass

        # Check for timestamp
        try:
            ts = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_TIMESTAMP)
            if ts > 0:
                options.append("TS")
        except:
            pass

        # Check for SACK
        try:
            sack = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_SACK)
            if sack > 0:
                options.append("SACK")
        except:
            pass

    except:
        pass
    return options

def detect_os(target):
    """TCP tabanlı işletim sistemi tespiti"""
    print("\n" + "=" * 60)
    print(f"İŞLETİM SİSTEMİ TESPİTİ: {target}")
    print("=" * 60)

    try:
        # İşletim sistemi bilgisi verebilecek yaygın portları dene
        test_ports = [80, 443, 22, 445, 3389, 548]  
        print("\n[+] Port taraması başlatılıyor...")
        print("-" * 60)
        
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((target, port)) == 0:
                    # Get TTL from the connection
                    ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    
                    # Get window size
                    window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    
                    # Get TCP options
                    tcp_options = get_tcp_options(sock)
                    
                    # Classify OS
                    os_type = classify_os(ttl, window_size, tcp_options)
                    print(f"[*] TTL: {ttl}, Window Size: {window_size}, TCP Options: {tcp_options}")
                    print(f"[*] Detected OS: {os_type}")
                    return os_type
                
                sock.close()
            except:
                continue
            finally:
                try:
                    sock.close()
                except:
                    pass
    except Exception as e:
        print(f"[!] TCP tespit hatası: {e}")
    
    # Host'un ayakta olup olmadığını kontrol et
    print("\n[+] Host durumu kontrol ediliyor...")
    print("-" * 60)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, 80))
        if result == 0:
            print("[*] Host ayakta fakat işletim sistemi tespiti başarısız")
        else:
            print("[!] Host kapalı")
        sock.close()
    except:
        print("[!] Host'a bağlantı kurulamadı")
    
    return "Tespit başarısız"

def get_ip_from_domain(domain):
    """Alan adını IP adresine dönüştür"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print("Hata: Alan adı çözümlenemedi")
        sys.exit(1)

def get_service_banner(sock):
    """Socket'ten servis banner'ını almaya çalış"""
    try:
        sock.settimeout(2)
        banner = sock.recv(1024)
        if banner:
            return banner.decode('utf-8', errors='ignore').strip()
    except:
        pass
    return None

def scan_port(target, port, open_ports):
    """Tek bir portu tara ve servisi belirle"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            # Servis banner'ını almaya çalış
            banner = get_service_banner(sock)
            if banner:
                service_info = f"Servis: {banner}"
            else:
                # Socket'ten servis adını almaya çalış
                try:
                    service = socket.getservbyport(port)
                    service_info = f"Servis: {service}"
                except:
                    service_info = "Servis: Bilinmiyor"
            open_ports.append((port, service_info))
        sock.close()
    except:
        pass

def port_scanner(target, start_port=1, end_port=1024):
    """Ana port tarama fonksiyonu"""
    try:
        target_ip = socket.inet_aton(target)
        target_ip = target
    except socket.error:
        target_ip = get_ip_from_domain(target)

    print("\n" + "=" * 60)
    print(f"PORT TARAMA BAŞLATILIYOR: {target} ({target_ip})")
    print("=" * 60)
    print(f"Başlangıç zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Port aralığı: {start_port}-{end_port}")
    print("-" * 60)
    
    # İşletim sistemi tespiti
    os_type = detect_os(target_ip)
    print("\n" + "=" * 60)
    print(f"TESPİT EDİLEN İŞLETİM SİSTEMİ: {os_type}")
    print("=" * 60)

    open_ports = []
    threads = []
    q = Queue()

    # Thread havuzu oluştur
    for port in range(start_port, end_port + 1):
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            scan_port(target_ip, port, open_ports)
            q.task_done()

    # Thread'leri başlat
    print("\n[+] Port taraması başlatılıyor...")
    for _ in range(100): 
        t = threading.Thread(target=worker)
        t.daemon = True
        threads.append(t)
        t.start()

    # Tüm thread'lerin tamamlanmasını bekle
    for t in threads:
        t.join()

    # Sonuçları yazdır
    print("\n" + "=" * 60)
    print("TARAMA SONUÇLARI")
    print("=" * 60)
    
    if open_ports:
        print("\nAÇIK PORTLAR VE SERVİSLER:")
        print("-" * 60)
        for port, service in sorted(open_ports):
            print(f"[+] Port {port}: {service}")
    else:
        print("\n[!] Belirtilen aralıkta açık port bulunamadı.")

    print("\n" + "=" * 60)
    print(f"TARAMA TAMAMLANDI: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("\n" + "=" * 60)
        print("KULLANIM")
        print("=" * 60)
        print("python port_scanner_ttl.py <OP_adresi> [baslangic_portu] [bitis_portu]")
        print("Örnek: python port_scanner_ttl.py example.com 1 1024")
        print("=" * 60)
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 65536

    port_scanner(target, start_port, end_port)

if __name__ == "__main__":
    main() 

    