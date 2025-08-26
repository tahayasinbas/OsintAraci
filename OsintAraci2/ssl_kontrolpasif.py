import requests
from datetime import datetime, timezone
import re


def parse_issuer_details(issuer_string):
    organization_name = "Bilinmiyor"
    common_name = "Bilinmiyor"
    full_name = issuer_string

    parts = [part.strip() for part in issuer_string.split(',')]
    for part in parts:
        if part.startswith("O="):
            organization_name = part[2:]
        elif part.startswith("CN="):
            common_name = part[3:]

    if organization_name == "Bilinmiyor" and common_name != "Bilinmiyor":
        display_issuer_name = common_name
    else:
        display_issuer_name = organization_name

    return {"organizationName": display_issuer_name, "commonName": common_name, "fullName": full_name}


def get_signature_algorithm(cert_id):
    try:
        print(f"\n[DETAYLI SERTİFİKA BİLGİSİ ALINIYOR: ID={cert_id}]")
        url = f"https://crt.sh/?id={cert_id}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        html_content = response.text

        clean_html = re.sub(r'<[^>]+>', ' ', html_content)
        clean_html = clean_html.replace('&nbsp;', ' ')
        clean_html = re.sub(r'\s+', ' ', clean_html)

        clean_match = re.search(r'Signature Algorithm:\s*(.*?)(?=\s*Issuer:|$)', clean_html, re.DOTALL)
        if clean_match:
            sig_algorithm = clean_match.group(1).strip()
            print(f"[BİLGİ] İmza algoritması temiz metinden bulundu: {sig_algorithm}")
            return sig_algorithm

        signature_match = re.search(r'(&nbsp;){3,}Signature\s*Algorithm:\s*([^<\n]+)', html_content)
        if signature_match:
            sig_algorithm = signature_match.group(2).strip()
            print(f"[BİLGİ] İmza algoritması nbsp ile bulundu: {sig_algorithm}")
            return sig_algorithm

        td_match = re.search(r'<td[^>]*>.*?Signature Algorithm:?\s*([^<\n]+)', html_content, re.DOTALL)
        if td_match:
            sig_algorithm = td_match.group(1).strip()
            print(f"[BİLGİ] İmza algoritması TD içinde bulundu: {sig_algorithm}")
            return sig_algorithm

        br_match = re.search(r'<td[^>]*>.*?<br\s*/?>\s*Signature Algorithm:?\s*([^<\n]+)', html_content, re.DOTALL)
        if br_match:
            sig_algorithm = br_match.group(1).strip()
            print(f"[BİLGİ] İmza algoritması BR ile bulundu: {sig_algorithm}")
            return sig_algorithm

        simple_match = re.search(r'Signature\s*Algorithm:\s*([^<\n]+)', html_content)
        if simple_match:
            sig_algorithm = simple_match.group(1).strip()
            print(f"[BİLGİ] İmza algoritması basit yöntemle bulundu: {sig_algorithm}")
            return sig_algorithm

        print("[UYARI] İmza algoritması hiçbir yöntemle bulunamadı.")
        return "Bilinmiyor"

    except Exception as e:
        print(f"[HATA] İmza algoritması alınamadı: {e}")
        return "Bilinmiyor"


def crtsh_verisini_goster(cert):
    print("\n[crt.sh JSON VERİSİNDEN SSL SERTİFİKA BİLGİLERİ (İŞLENİYOR)]")

    try:
        not_before = None
        not_after = None

        not_before_str = cert.get("not_before", "")
        if not_before_str:
            try:
                if "T" in not_before_str:
                    not_before = datetime.fromisoformat(not_before_str.split('.')[0]).replace(tzinfo=timezone.utc)
                else:
                    try:
                        not_before = datetime.strptime(not_before_str, "%Y%m%d%H%M%S%fZ").replace(tzinfo=timezone.utc)
                    except ValueError:
                        not_before = datetime.strptime(not_before_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError as e:
                print(f"[UYARI] Not Before tarihi işlenemedi: {e}. Tarih: {not_before_str}")

        not_after_str = cert.get("not_after", "")
        if not_after_str:
            try:
                if "T" in not_after_str:
                    not_after = datetime.fromisoformat(not_after_str.split('.')[0]).replace(tzinfo=timezone.utc)
                else:
                    try:
                        not_after = datetime.strptime(not_after_str, "%Y%m%d%H%M%S%fZ").replace(tzinfo=timezone.utc)
                    except ValueError:
                        not_after = datetime.strptime(not_after_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError as e:
                print(f"[UYARI] Not After tarihi işlenemedi: {e}. Tarih: {not_after_str}")

        kalan_gun = 0
        total_duration_days = 0
        now = datetime.now(timezone.utc)

        if not_after and not_before:
            kalan_gun = (not_after - now).days
            total_duration_days = (not_after - not_before).days
        elif not_after:
            kalan_gun = (not_after - now).days

        issuer_name_str = cert.get('issuer_name', 'Bilinmiyor')
        issuer_details = parse_issuer_details(issuer_name_str)
        common_name_str = cert.get('common_name', 'Bilinmiyor')

        crtsh_id = cert.get('id', 'Bilinmiyor')

        signature_algorithm = "N/A (crt.sh)"
        if crtsh_id != 'Bilinmiyor':
            signature_algorithm = get_signature_algorithm(crtsh_id)

        print(f"Domain              : {common_name_str}")
        print(f"Başlangıç Tarihi    : {not_before.strftime('%Y-%m-%d %H:%M:%S UTC') if not_before else 'Bilinmiyor'}")
        print(f"Bitiş Tarihi        : {not_after.strftime('%Y-%m-%d %H:%M:%S UTC') if not_after else 'Bilinmiyor'}")
        print(f"Kalan Gün           : {kalan_gun if not_after else 'N/A'} gün")
        print(f"Verilen Kurum       : {issuer_name_str}")
        print(f"Sertifika ID        : {crtsh_id}")
        print(f"İmza Algoritması    : {signature_algorithm}")  # YENİ: İmza algoritmasını yazdır
        print(f"Seri Numarası       : {cert.get('serial_number', 'Bilinmiyor')}")
        print(f"Giriş Zamanı        : {cert.get('entry_timestamp', 'Bilinmiyor')}")

        if not_after and kalan_gun <= 0:
            print(f"[UYARI] Sertifika süresi dolmuş!")
        elif not_after and kalan_gun <= 30:
            print(f"[UYARI] Sertifika yakında sona erecek ({kalan_gun} gün kaldı)!")

        return {
            "not_before": not_before,
            "not_after": not_after,
            "subject": {"commonName": common_name_str, "raw": cert.get('name_value', common_name_str)},
            "issuer": issuer_details,
            "kalan_gun": kalan_gun if not_after else -1,
            "total_duration_days": total_duration_days if total_duration_days > 0 else 365,
            "serial_number": cert.get('serial_number', 'Bilinmiyor'),
            "self_signed": False,
            "signature_algorithm": signature_algorithm,
            "tls_version": "N/A (crt.sh)",
            "crtsh_id": crtsh_id,
            "crtsh_entry_timestamp": cert.get('entry_timestamp', 'Bilinmiyor')
        }

    except Exception as e:
        print(f"[HATA] Sertifika verisi işlenemedi: {e}")
        return {"error": f"Sertifika verisi işlenemedi: {e}", "self_signed": None}


def crtsh_ssl_bilgisi(domain):
    print(f"\n[crt.sh ÜZERİNDEN SSL SERTİFİKA BİLGİLERİ SORGULANIYOR: {domain}]")

    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        cert_list = response.json()

        if not cert_list:
            print(f"[BİLGİ] {domain} için sertifika bulunamadı.")
            return {"error": f"{domain} için sertifika bulunamadı.", "self_signed": None}

        valid_certs = []
        now_utc = datetime.now(timezone.utc)

        for cert_data in cert_list:
            not_after_str = cert_data.get("not_after", "")
            if not not_after_str: continue

            try:
                if "T" in not_after_str:
                    not_after_dt = datetime.fromisoformat(not_after_str.split('.')[0]).replace(tzinfo=timezone.utc)
                elif "Z" in not_after_str:
                    not_after_dt = datetime.strptime(not_after_str, "%Y%m%d%H%M%S%fZ").replace(tzinfo=timezone.utc)
                else:
                    print(f"[UYARI] Bilinmeyen not_after formatı: {not_after_str} - {cert_data.get('id')}")
                    continue

                cert_data["parsed_not_after"] = not_after_dt  # Sıralama için

                if not_after_dt > now_utc:
                    valid_certs.append(cert_data)

            except (ValueError, KeyError) as e:
                print(
                    f"[UYARI] Sertifika tarihi ayrıştırılamadı veya anahtar hatası: {e} - Sertifika ID: {cert_data.get('id')}")
                continue

        if not valid_certs:
            print(
                f"[UYARI] {domain} için geçerli (süresi dolmamış) sertifika bulunamadı. Süresi dolmuş olanlar listeleniyor.")
            if cert_list:
                cert_list.sort(key=lambda x: x.get("parsed_not_after", datetime.min.replace(tzinfo=timezone.utc)),
                               reverse=True)
                print(f"[BİLGİ] En son süresi dolmuş sertifika gösterilecek.")
                return crtsh_verisini_goster(cert_list[0])
            else:
                return {"error": f"{domain} için hiçbir sertifika verisi bulunamadı.", "self_signed": None}

        valid_certs.sort(key=lambda x: x.get("parsed_not_after"), reverse=True)

        print(f"[BİLGİ] En uzun süre geçerli olan sertifika gösterilecek.")
        return crtsh_verisini_goster(valid_certs[0])

    except requests.exceptions.Timeout:
        print(f"[HATA] crt.sh zaman aşımına uğradı.")
        return {"error": "crt.sh isteği zaman aşımına uğradı.", "self_signed": None}
    except requests.exceptions.RequestException as e:
        print(f"[HATA] crt.sh verisi alınamadı: {e}")
        return {"error": f"crt.sh verisi alınamadı: {e}", "self_signed": None}
    except ValueError as e:  # JSON parse hatası
        print(f"[HATA] JSON verisi ayrıştırılamadı: {e}")
        return {"error": f"JSON verisi ayrıştırılamadı: {e}", "self_signed": None}
    except Exception as e:
        print(f"[HATA] Beklenmeyen bir hata oluştu: {e}")
        return {"error": f"Beklenmeyen bir hata oluştu: {e}", "self_signed": None}


def ana_fonksiyon_cli():
    print("SSL Sertifika Bilgisi Kontrolü (crt.sh CLI)")
    print("------------------------------------------")

    while True:
        domain = input("\nDomain girin (çıkmak için 'q'): ").strip()

        if domain.lower() == 'q':
            print("\nProgram sonlandırılıyor...")
            break

        if not domain:
            print("[HATA] Lütfen geçerli bir domain girin.")
            continue

        result = crtsh_ssl_bilgisi(domain)
        if result and "error" in result:
            print(f"CLI Sonuç: Hata - {result['error']}")
        elif result:
            print(f"CLI Sonuç: Başarılı (Detaylar yukarıda loglandı). Kalan gün: {result.get('kalan_gun')}")


if __name__ == "__main__":
    ana_fonksiyon_cli()