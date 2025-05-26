import socket
import sys
import time
from datetime import datetime
import threading
from queue import Queue

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
                    # Servis banner'ını almaya çalış
                    banner = get_service_banner(sock)
                    if banner:
                        banner = banner.lower()
                        if any(x in banner for x in ['windows', 'iis', 'microsoft', 'asp.net']):
                            print("[*] TCP banner'ı Windows işaret ediyor")
                            return "Windows"
                        elif any(x in banner for x in ['apache', 'nginx', 'linux', 'ubuntu', 'debian']):
                            print("[*] TCP banner'ı Linux/Unix işaret ediyor")
                            return "Linux/Unix"
                        elif any(x in banner for x in ['macos', 'darwin', 'apple', 'afp', 'bonjour']):
                            print("[*] TCP banner'ı macOS işaret ediyor")
                            return "macOS"
                
                # TCP pencere boyutunu al
                window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                
                # TCP pencere boyutuna göre işletim sistemi tahmini
                if window_size > 65535:
                    print("[*] TCP pencere boyutu Windows işaret ediyor")
                    return "Windows"
                elif 32768 <= window_size <= 65535:
                    print("[*] TCP pencere boyutu macOS işaret ediyor")
                    return "macOS"
                elif window_size > 0:
                    print("[*] TCP pencere boyutu Linux/Unix işaret ediyor")
                    return "Linux/Unix"
                
                # TCP seçeneklerini kontrol et
                try:
                    tcp_options = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                    if tcp_options > 0:
                        # macOS genellikle belirli TCP seçenekleri kullanır
                        if tcp_options == 1460:  # macOS'un tipik MSS değeri
                            print("[*] TCP seçenekleri macOS işaret ediyor")
                            return "macOS"
                except:
                    pass
                
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

    