import whois
import dns.resolver
import requests
import socket
from scapy.all import IP, TCP, sr1, sr, conf
import subprocess
import re
import sys
import urllib3

def whois_sorgula(domain):
    try:
        bilgi = whois.whois(domain)
        print("\n[WHOIS BİLGİLERİ]")
        print(f"Domain: {bilgi.domain_name}")
        print(f"Registrar: {bilgi.registrar}")
        print(f"Kayıt Tarihi: {bilgi.creation_date}")
        print(f"Bitiş Tarihi: {bilgi.expiration_date}")
        print(f"Name Serverlar: {bilgi.name_servers}")
        print(bilgi)
        return bilgi
    except Exception as e:
        print(f"[!] WHOIS hatası: {e}")
        return None

def dns_kayitlarini_al(domain):
    print("\n[DNS KAYITLARI]")
    sonuc = {}  
    kayit_turleri = ['A', 'MX', 'NS', 'TXT']
    
    for tur in kayit_turleri:
        sonuc[tur] = []  
        try:
            cevaplar = dns.resolver.resolve(domain, tur)
            for cevap in cevaplar:
                kayit = cevap.to_text()
                print(f"{tur} Kaydı: {kayit}")
                sonuc[tur].append(kayit)  
        except Exception as e:
            print(f"{tur} kaydı alınamadı: {e}")
            sonuc[tur].append(f"Hata: {str(e)}")  
    
    return sonuc  

def get_server_info(url):
    if not url.startswith('http'):
        url = f'http://{url}'
    
    try:
        response = requests.get(url, timeout=5)
        server_info = {
            'server': response.headers.get('Server', 'Belirtilmemiş'),
            'x_powered_by': response.headers.get('X-Powered-By', 'Belirtilmemiş'),
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }
        return server_info
    except Exception as e:
        return {'error': str(e)}

def get_banner(domain, port):
    try:
        ip = socket.gethostbyname(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return f"Bağlantı hatası: {e}"

def scan_common_ports(domain):
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-ALT"
    }
    
    results = {}
    for port, service in common_ports.items():
        banner = get_banner(domain, port)
        if "Bağlantı hatası" not in banner:
            results[f"{port} ({service})"] = banner
    
    return results


def syn_port_scan(domain, ports=None):
    from scapy.all import IP, TCP, sr1, sr, conf
    
    conf.verb = 0
    
    if ports is None:
        ports = [21, 22, 25, 80, 443, 3306, 8080]
    

    ip = socket.gethostbyname(domain)
    print(f"[+] SYN taraması başlatılıyor: {domain} ({ip})")
    
    results = {}
    
    for port in ports:
        print(f"[-] Port {port} kontrol ediliyor...")
        
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=2)
        
        if response is None:
            results[port] = "Filtrelenmiş/Timeout"
        elif response.haslayer(TCP):
            tcp_flags = response.getlayer(TCP).flags
            
            if tcp_flags == 0x12:  
                rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                sr(rst_packet, timeout=1)
                results[port] = "AÇIK"
            elif tcp_flags == 0x14: 
                results[port] = "KAPALI"
            else:
                results[port] = f"BEKLENMEYEN YANIT: {tcp_flags}"
        else:
            results[port] = "BEKLENMEYEN YANIT TÜRÜ"
            
    return results

def detect_os_and_versions(target, ports_to_scan=None):

    results = {
        'os': 'Bilinmiyor',
        'services': {}
    }
    
    # 1. Ping TTL ile basit OS tespiti
    try:
        cmd = "ping -n 1 " if sys.platform.lower() == "win32" else "ping -c 1 "
        output = subprocess.check_output(cmd + target, shell=True, text=True)
        ttl_match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                results['os'] = 'Muhtemelen Linux/Unix (TTL: {})'.format(ttl)
            elif ttl <= 128:
                results['os'] = 'Muhtemelen Windows (TTL: {})'.format(ttl)
    except:
        pass
    
    # 2. Yaygın portları kontrol et
    common_ports = {
        21: "FTP", 
        22: "SSH", 
        23: "Telnet",
        25: "SMTP", 
        80: "HTTP", 
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL", 
        3389: "RDP",
        5432: "PostgreSQL", 
        8080: "HTTP-ALT"
    }
    
    if ports_to_scan is not None:
        ports_dict = {}
        for port in ports_to_scan:
            port = int(port)  
            ports_dict[port] = common_ports.get(port, "Bilinmiyor")
        common_ports = ports_dict
    
    print(f"[+] {target} için {len(common_ports)} port taranıyor: {list(common_ports.keys())}")
    
    ip = socket.gethostbyname(target)
    for port, service in common_ports.items():
        print(f"[-] Port {port} kontrol ediliyor...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            
            conn_result = s.connect_ex((ip, port))
            
            if conn_result == 0:
                print(f"  Port {port}: AÇIK")
                
   
                if port in [80, 443, 8080]:
                    protocol = "https" if port == 443 else "http"
                    url = f"{protocol}://{target}"
                    
                    try:
                        response = requests.get(url, timeout=3, verify=False)
                        server = response.headers.get('Server', '')
                        powered_by = response.headers.get('X-Powered-By', '')
                        
                        version_info = []
                        if server:
                            version_info.append(f"Server: {server}")
                        if powered_by:
                            version_info.append(f"Powered by: {powered_by}")
                            
                        results['services'][port] = {
                            'name': service,
                            'version': ', '.join(version_info) if version_info else 'Bilinmiyor',
                            'banner': str(dict(response.headers))
                        }
                        
                        if 'IIS' in server:
                            results['os'] = 'Muhtemelen Windows'
                        elif any(x in server for x in ['Apache', 'nginx', 'lighttpd']):
                            results['os'] = 'Muhtemelen Linux/Unix'
                    except:
                        results['services'][port] = {'name': service, 'version': 'Bilinmiyor', 'banner': 'Alınamadı'}
                
                elif port == 22:
                    try:
                        s.settimeout(2)
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        results['services'][port] = {'name': 'SSH', 'version': banner, 'banner': banner}
                        
                        if 'ubuntu' in banner.lower():
                            results['os'] = 'Muhtemelen Ubuntu Linux'
                        elif 'debian' in banner.lower():
                            results['os'] = 'Muhtemelen Debian Linux'
                        elif 'openssh' in banner.lower():
                            results['os'] = 'Muhtemelen Unix/Linux'
                    except:
                        results['services'][port] = {'name': 'SSH', 'version': 'Bilinmiyor', 'banner': 'Alınamadı'}
                
                elif port == 21:
                    try:
                        s.settimeout(2)
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        results['services'][port] = {'name': 'FTP', 'version': banner, 'banner': banner}
                        
                        if any(x in banner.lower() for x in ['windows', 'microsoft']):
                            results['os'] = 'Muhtemelen Windows'
                        elif any(x in banner.lower() for x in ['unix', 'linux', 'ubuntu', 'debian']):
                            results['os'] = 'Muhtemelen Linux/Unix'
                    except:
                        results['services'][port] = {'name': 'FTP', 'version': 'Bilinmiyor', 'banner': 'Alınamadı'}
                
                elif port == 25:
                    try:
                        s.settimeout(2)
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        results['services'][port] = {'name': 'SMTP', 'version': banner, 'banner': banner}
                    except:
                        results['services'][port] = {'name': 'SMTP', 'version': 'Bilinmiyor', 'banner': 'Alınamadı'}
                        
                else:
                    try:
                        s.settimeout(2)
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        results['services'][port] = {
                            'name': service,
                            'version': banner[:50] + '...' if len(banner) > 50 else banner,
                            'banner': banner[:100] + '...' if len(banner) > 100 else banner
                        }
                    except:
                        results['services'][port] = {'name': service, 'version': 'Bilinmiyor', 'banner': 'Alınamadı'}
            
            s.close()
        except:
            continue
    
    return results

def detect_services_for_open_ports(target, ports_to_check):

    urllib3.disable_warnings()
    
    results = {
        'os': 'Bilinmiyor',
        'services': {}
    }
    
    try:
        cmd = "ping -n 1 " if sys.platform.lower() == "win32" else "ping -c 1 "
        output = subprocess.check_output(cmd + target, shell=True, text=True)
        ttl_match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                results['os'] = 'Muhtemelen Linux/Unix (TTL: {})'.format(ttl)
            elif ttl <= 128:
                results['os'] = 'Muhtemelen Windows (TTL: {})'.format(ttl)
    except:
        pass
    
    service_names = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-ALT"
    }
    
    try:
        ip = socket.gethostbyname(target)
        print(f"[+] {target} ({ip}) için {len(ports_to_check)} port taranıyor")
    except socket.gaierror:
        print(f"[-] Hedef çözümlenemedi: {target}")
        return results
    
    for port in ports_to_check:
        port = int(port)  
        service = service_names.get(port, "Bilinmiyor")
        print(f"[-] Port {port} ({service}) inceleniyor...")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            conn_result = s.connect_ex((ip, port))
            
            if conn_result == 0:
                # Port açık
                print(f"  Port {port}: AÇIK")
                results['services'][port] = {
                    'name': service,
                    'version': 'Tespit ediliyor...',
                    'banner': 'Tespit ediliyor...',
                    'status': 'AÇIK'
                }
                
                # HTTP/HTTPS servisleri için
                if port in [80, 443, 8080, 8443]:
                    try:
                        protocol = "https" if port in [443, 8443] else "http"
                        url = f"{protocol}://{target}:{port}"
                        
                        response = requests.get(url, timeout=3, verify=False)
                        server = response.headers.get('Server', '')
                        powered_by = response.headers.get('X-Powered-By', '')
                        
                        version_info = []
                        if server:
                            version_info.append(f"Server: {server}")
                        if powered_by:
                            version_info.append(f"Powered by: {powered_by}")
                            
                        results['services'][port]['version'] = ', '.join(version_info) if version_info else 'Bilinmiyor'
                        results['services'][port]['banner'] = str(dict(response.headers))
                        
                        # Web sunucu türünden OS tahmini
                        if 'IIS' in server:
                            results['os'] = 'Muhtemelen Windows'
                        elif any(x in server for x in ['Apache', 'nginx', 'lighttpd']):
                            results['os'] = 'Muhtemelen Linux/Unix'
                    except Exception as e:
                        print(f"  HTTP isteği hatası: {e}")
                        results['services'][port]['version'] = 'Bilinmiyor'
                        results['services'][port]['banner'] = 'Alınamadı'
                
                # Diğer servisler için banner bilgisini al
                else:
                    try:
                        # SSH için
                        if port == 22:
                            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            results['services'][port]['version'] = banner
                            results['services'][port]['banner'] = banner
                            
                            # SSH banner'ından OS tahmini
                            if 'ubuntu' in banner.lower():
                                results['os'] = 'Muhtemelen Ubuntu Linux'
                            elif 'debian' in banner.lower():
                                results['os'] = 'Muhtemelen Debian Linux'
                            elif 'openssh' in banner.lower():
                                results['os'] = 'Muhtemelen Unix/Linux'
                        
                        # FTP için
                        elif port == 21:
                            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            results['services'][port]['version'] = banner
                            results['services'][port]['banner'] = banner
                            
                            # FTP banner'ından OS tahmini
                            if any(x in banner.lower() for x in ['windows', 'microsoft']):
                                results['os'] = 'Muhtemelen Windows'
                            elif any(x in banner.lower() for x in ['unix', 'linux', 'ubuntu', 'debian']):
                                results['os'] = 'Muhtemelen Linux/Unix'
                        
                        # SMTP için
                        elif port == 25:
                            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            results['services'][port]['version'] = banner
                            results['services'][port]['banner'] = banner
                        
                        # Diğer servisler için
                        else:
                            try:
                                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                                if not banner:  # Eğer banner boşsa özel komut göndermeyi dene
                                    s.send(b"HELP\r\n")  
                                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            except:
                                banner = "Banner alınamadı"
                                
                            results['services'][port]['version'] = banner[:50] + '...' if len(banner) > 50 else banner
                            results['services'][port]['banner'] = banner[:100] + '...' if len(banner) > 100 else banner
                    except Exception as e:
                        results['services'][port]['version'] = 'Bilinmiyor'
                        results['services'][port]['banner'] = f'Hata: {str(e)}'
            else:
                # Port kapalı
                print(f"  Port {port}: KAPALI")
                results['services'][port] = {
                    'name': service,
                    'version': 'N/A',
                    'banner': 'N/A',
                    'status': 'KAPALI'
                }
            
            s.close()
        except socket.timeout:
            # Zaman aşımı - muhtemelen filtrelenmiş
            print(f"  Port {port}: FİLTRELENMİŞ (Timeout)")
            results['services'][port] = {
                'name': service,
                'version': 'N/A',
                'banner': 'N/A',
                'status': 'FİLTRELENMİŞ'
            }
        except Exception as e:
            # Diğer hatalar
            print(f"  Port {port} tarama hatası: {e}")
            results['services'][port] = {
                'name': service,
                'version': 'N/A',
                'banner': f'Hata: {str(e)}',
                'status': 'HATA'
            }
    
    return results

def quick_port_scan(domain, ports=None):
    """
    Basit soket bağlantısı ile port taraması yapar ve banner bilgisi toplar.
    SYN taramasından farklı olarak tam TCP bağlantısı kurar.
    """
    if ports is None:
        ports = [21, 22, 25, 80, 443, 3306, 8080]
    
    # Hedef IP adresini çözümle
    ip = socket.gethostbyname(domain)
    print(f"[+] Hızlı port taraması başlatılıyor: {domain} ({ip})")
    
    results = {}
    
    for port in ports:
        print(f"[-] Port {port} kontrol ediliyor...")
        
        try:
            # TCP bağlantısı kur
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            conn_result = s.connect_ex((ip, port))
            
            if conn_result == 0:
                # Port açık
                try:
                    # Banner almayı dene
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    results[port] = f"AÇIK - {banner}" if banner else "AÇIK"
                except:
                    results[port] = "AÇIK"
            else:
                # Port kapalı
                results[port] = "KAPALI"
                
            s.close()
        except socket.timeout:
            results[port] = "Filtrelenmiş/Timeout"
        except Exception as e:
            results[port] = f"HATA: {str(e)}"
    
    return results

if __name__ == "__main__":
    domain = input("Domain girin: ")
#   whois_sorgula(domain)
#   dns_kayitlarini_al(domain)
#   server_info = get_server_info(domain)
#   banner = scan_common_ports(domain)
#    sonuc = syn_port_scan(domain)
    open_ports = [80, 443]
    sonuc = detect_services_for_open_ports(domain, open_ports)
    print(sonuc)
    bilgi = dns_kayitlarini_al(domain)
    print(bilgi)
#   print(server_info)
