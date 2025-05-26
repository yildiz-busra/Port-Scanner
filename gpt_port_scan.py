import socket
import struct
import sys
import platform
import time

# Servis adını döndür (port numarasından)
def servis_adi(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Bilinmeyen servis"

# Port taraması yap
def port_taramasi(ip, baslangic_port=1, bitis_port=100):
    print(f"\n🔍 {ip} adresinde {baslangic_port}-{bitis_port} arası TCP portlar taranıyor...\n")
    acik_portlar = []

    for port in range(baslangic_port, bitis_port + 1):
        try:
            soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soket.settimeout(0.3)
            sonuc = soket.connect_ex((ip, port))
            if sonuc == 0:
                servis = servis_adi(port)
                print(f"[+] Port {port} açık ({servis})")
                acik_portlar.append((port, servis))
            soket.close()
        except:
            continue

    if not acik_portlar:
        print("🔒 Açık port bulunamadı.")
    return acik_portlar

# TTL değeri ile basit işletim sistemi tahmini
def ttl_os_tahmini(ip):
    print(f"\n🧠 TTL değerine göre işletim sistemi tahmini ({ip})")

    try:
        # Raw socket ile ICMP Echo Request (Ping) gönder
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(1)

        # ICMP başlığı (tip, kod, checksum, id, sıra no)
        icmp_header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
        icmp_packet = icmp_header
        s.sendto(icmp_packet, (ip, 0))

        start = time.time()
        data, addr = s.recvfrom(1024)
        end = time.time()

        ip_header = data[0:20]
        ttl = struct.unpack('!B', ip_header[8:9])[0]

        print(f"🎯 TTL değeri: {ttl}")

        # Basit tahminler
        if ttl >= 128:
            print("💡 Tahmini OS: Windows")
        elif ttl >= 64:
            print("💡 Tahmini OS: Linux / Unix")
        else:
            print("💡 Tahmini OS: Bilinmiyor")

    except PermissionError:
        print("⛔ Bu işlem için yönetici (admin/root) izni gerekir.")
    except socket.timeout:
        print("⏱ Yanıt alınamadı. TTL tahmini yapılamadı.")
    except Exception as e:
        print("⚠ Hata oluştu:", e)

# Ana fonksiyon
def main():
    print("🛰  Ağ Tarama ve OS Tahmini Programı (nmap kullanmadan)\n")
    ip = input("Hedef IP adresini girin: ")

    port_taramasi(ip, 1, 100)
    ttl_os_tahmini(ip)

if __name__ == "__main__":
    main()
