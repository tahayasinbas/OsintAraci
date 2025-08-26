import json
import re
from datetime import datetime

def temizle_metin(metin):
    """Metni temizler: gereksiz boşluklar, satır sonları ve HTML etiketlerini kaldırır"""
    if isinstance(metin, list):
        # Liste ise birleştir
        metin = ' '.join(metin)
    
    # HTML etiketlerini kaldır
    metin = re.sub(r'<.*?>', '', metin)
    
    # Satır sonlarını ve fazla boşlukları temizle
    metin = re.sub(r'\r\n|\n|\r', ' ', metin)
    metin = re.sub(r'\t', ' ', metin)
    metin = re.sub(r'\s+', ' ', metin)
    
    return metin.strip()

def cikart_tarih(metin):
    """Metinden tarihleri çıkarır"""
    # Farklı tarih formatlarını tanımak için regex kalıpları
    tarih_kaliplari = [
        r'(\d{1,2}\.\d{1,2}\.\d{4})', # 26.02.2025
        r'(\d{1,2}/\d{1,2}/\d{4})',   # 26/02/2025
        r'(\d{1,2}-\d{1,2}-\d{4})',   # 26-02-2025
        r'(\d{1,2} [A-Za-zğüşıöçĞÜŞİÖÇ]+ \d{4})' # 26 Şubat 2025
    ]
    
    tarihler = []
    for kalip in tarih_kaliplari:
        bulunan_tarihler = re.findall(kalip, metin)
        tarihler.extend(bulunan_tarihler)
    
    return tarihler

def cikart_kisi_sayisi(metin):
    """Metinden etkilenen kişi sayısını çıkarır"""
    # Kişi sayısı genellikle bir sayı ve "kişi", "kullanıcı" vb. kelimelerle birlikte geçer
    kisi_kaliplari = [
        r'(\d{1,3}(?:\.\d{3})*(?:\,\d+)?) kişi',
        r'(\d{1,3}(?:\.\d{3})*(?:\,\d+)?) kullanıcı',
        r'(\d{1,3}(?:\.\d{3})*(?:\,\d+)?) müşteri',
        r'(\d{1,3}(?:\.\d{3})*(?:\,\d+)?) abone'
    ]
    
    for kalip in kisi_kaliplari:
        bulunan = re.search(kalip, metin)
        if bulunan:
            # Nokta ile ayrılmış sayıyı düzgün biçimde döndür
            return bulunan.group(1)
    
    # Bazı durumlarda sadece sayı olabilir, madde işaretinden sonra
    genel_sayi = re.search(r'(\d{1,3}(?:\.\d{3})*(?:\,\d+)?) (?:ilgili kişi|veri)', metin)
    if genel_sayi:
        return genel_sayi.group(1)
    
    return None

def cikart_veri_turleri(metin):
    """Metinden sızan veri türlerini çıkarır"""
    veri_turleri = [
        "TC kimlik", "T.C. kimlik", "kimlik numarası",
        "telefon", "adres", "e-posta", "email", "e-mail",
        "kredi kartı", "banka hesap", "IP", "şifre", "parola",
        "sağlık verisi", "verisi"
    ]
    
    bulunan_turler = []
    
    for tur in veri_turleri:
        if tur.lower() in metin.lower():
            bulunan_turler.append(tur)
    
    return bulunan_turler

def cikart_iletisim_bilgileri(metin):
    """Metinden iletişim bilgilerini çıkarır"""
    # Telefon numarası
    telefon_kaliplari = [
        r'(\d{4}\s\d{3}\s\d{2}\s\d{2})',  # 0850 288 80 80
        r'(0\d{3}\s\d{3}\s\d{2}\s\d{2})'   # 0850 288 80 80
    ]
    
    telefonlar = []
    for kalip in telefon_kaliplari:
        bulunan = re.findall(kalip, metin)
        telefonlar.extend(bulunan)
    
    # Adres için belirli bir kalıp tanımlamak zor, "cadde", "sokak" gibi kelimeler aranabilir
    adresler = []
    adres_satiri = re.search(r'"([^"]*(?:cadde|cd|cad|sokak|sk|mahalle|mah)[^"]*)"', metin, re.IGNORECASE)
    if adres_satiri:
        adresler.append(adres_satiri.group(1))
    
    return {
        "telefonlar": telefonlar,
        "adresler": adresler
    }

def formatla_icerik(icerik, baslik, tarihler, kisi_sayisi, veri_turleri, iletisim):
    """İçeriği daha okunaklı bir şekilde formatlar"""
    formatted = f"Başlık: {baslik}\n\n"
    
    # Özet bilgileri ekle
    formatted += "ÖZET BİLGİLER:\n"
    if tarihler:
        formatted += f"• İhlal Tarihi: {', '.join(tarihler)}\n"
    if kisi_sayisi:
        formatted += f"• Etkilenen Kişi Sayısı: {kisi_sayisi}\n"
    if veri_turleri:
        formatted += f"• Sızan Veri Türleri: {', '.join(veri_turleri)}\n"
    if iletisim["telefonlar"]:
        formatted += f"• İletişim: {', '.join(iletisim['telefonlar'])}\n"
    
    formatted += "\nDETAYLAR:\n"
    formatted += icerik
    
    return formatted

def veri_temizle_ve_analiz_et():
    """bilgi.json'dan verileri okur, temizler, analiz eder ve yeni format oluşturur"""
    try:
        with open("KvkkVeriIhlali/vericrawler/bilgi.json", "r", encoding="utf-8") as f:
            veri = json.load(f)
        
        temiz_veri = []
        
        for item in veri:
            baslik = temizle_metin(item["AramaSonucuBaslik"])
            icerik_ham = temizle_metin(item["AramaSonucYazi"])
            
            # Veri ihlali bildirimi değilse atla (opsiyonel)
            if "veri ihlali" not in baslik.lower() and "ihlal bildirimi" not in icerik_ham.lower():
                # İçeriği temizle ama analiz etme
                temiz_veri.append({
                    "baslik": baslik,
                    "icerik": icerik_ham,
                    "veri_ihlali_mi": False,
                    "ozet": "Bu bir veri ihlali bildirimi değildir."
                })
                continue
            
            # Tarih, kişi sayısı ve veri türlerini çıkar
            tarihler = cikart_tarih(icerik_ham)
            kisi_sayisi = cikart_kisi_sayisi(icerik_ham)
            veri_turleri = cikart_veri_turleri(icerik_ham)
            iletisim_bilgileri = cikart_iletisim_bilgileri(icerik_ham)
            
            # Formatlanmış içerik oluştur
            formatli_icerik = formatla_icerik(
                icerik_ham, baslik, tarihler, kisi_sayisi, veri_turleri, iletisim_bilgileri
            )
            
            # Temiz veri sözlüğü oluştur
            temiz_item = {
                "baslik": baslik,
                "icerik": icerik_ham,
                "formatli_icerik": formatli_icerik,
                "veri_ihlali_mi": True,
                "tarihler": tarihler,
                "kisi_sayisi": kisi_sayisi,
                "veri_turleri": veri_turleri,
                "iletisim_bilgileri": iletisim_bilgileri,
                "ozet": f"İhlal Tarihi: {tarihler[0] if tarihler else 'Belirtilmemiş'}, Etkilenen: {kisi_sayisi or 'Belirtilmemiş'}"
            }
            
            temiz_veri.append(temiz_item)
        
        # Temizlenmiş veriyi bir dosyaya yaz
        with open("KvkkVeriIhlali/vericrawler/temiz_bilgi.json", "w", encoding="utf-8") as f:
            json.dump(temiz_veri, f, ensure_ascii=False, indent=2)
            
        return temiz_veri
        
    except Exception as e:
        print(f"Hata: {e}")
        return []

if __name__ == "__main__":
    # Test et
    temiz_veri = veri_temizle_ve_analiz_et()
    print(f"{len(temiz_veri)} adet veri temizlendi ve analiz edildi.")
