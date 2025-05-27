import socket
import sys
import time
from datetime import datetime
import threading
from queue import Queue
from scapy.all import IP, TCP, sr1, conf

def detect_os(target):
    """Scapy ile TCP/IP fingerprinting kullanarak işletim sistemi tespiti"""
    print("\n" + "=" * 60)
    print(f"İŞLETİM SİSTEMİ TESPİTİ (Scapy): {target}")
    print("=" * 60)

    conf.verb = 0  # Scapy'nin sessiz çalışması için

    ports_to_try = [80, 443, 22, 445]
    response = None

    for port in ports_to_try:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        print(f"[*] SYN paketi gönderiliyor: Port {port}")
        response = sr1(pkt, timeout=2)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            break

    if not response:
        print("[!] Hedef cevap vermedi veya portlar kapalı")
        return "Tespit başarısız"

    ttl = response.ttl
    window = response.getlayer(TCP).window

    print(f"[+] Alınan TTL: {ttl}")
    print(f"[+] TCP Window Size: {window}")

    # Heuristik OS tespiti
    if ttl >= 120:
        if 8192 <= window <= 65535:
            os_guess = "Windows"
        else:
            os_guess = "Muhtemelen Windows"
    elif 60 <= ttl <= 70:
        if 5840 <= window <= 14600:
            os_guess = "Linux"
        elif 14600 < window < 30000:
            os_guess = "macOS veya BSD"
        else:
            os_guess = "Linux/Unix"
    elif ttl > 200:
        os_guess = "macOS / FreeBSD / Cisco"
    else:
        os_guess = "Tespit başarısız"

    print(f"[+] Tahmini İşletim Sistemi: {os_guess}")
    return os_guess

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
                try:
                    service = socket.getservbyport(port)
                    service_info = f"Servis: {service}"
                except:
                    service_info = "Servis: Bilinmiyor"
            open_ports.append((port, service_info))
        sock.close()
    except:
        pass

def port_scanner(target, start_port, end_port):
    """Ana port tarama fonksiyonu"""
    try:
        socket.inet_aton(target)
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

    for port in range(start_port, end_port + 1):
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            scan_port(target_ip, port, open_ports)
            q.task_done()

    print("\n[+] Port taraması başlatılıyor...")
    for _ in range(100): 
        t = threading.Thread(target=worker)
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

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
        print("python port_scanner_scapy.py <IP_adresi> [baslangic_portu] [bitis_portu]")
        print("Örnek: python port_scanner_scapy.py example.com 1 1024")
        print("=" * 60)
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 65535

    port_scanner(target, start_port, end_port)

if __name__ == "__main__":
    main()
