
from googlesearch import search

def dork_ara(domain, secilen_dorklar=None, num_results=5):

    print("\n[GOOGLE DORKS SONUÇLARI]")
    
    tum_dorklar = {
        "pdf_dosyalari": {"aciklama": "PDF dosyaları", "sorgu": f"site:{domain} filetype:pdf"},
        "acik_dizinler": {"aciklama": "Açık dizinler", "sorgu": f"site:{domain} intitle:index.of"},
        "login_sayfalari": {"aciklama": "Login sayfaları", "sorgu": f"site:{domain} inurl:login"},
        "sifre_sayfalar": {"aciklama": "Şifre içeren sayfalar", "sorgu": f"site:{domain} password"},
        "sql_dosyalari": {"aciklama": "SQL dosyaları", "sorgu": f"site:{domain} ext:sql"},
        "alt_domainler": {"aciklama": "Alt domainler", "sorgu": f"site:*.{domain} -www"}
    }
    
    if secilen_dorklar is None:
        secilen_dorklar = list(tum_dorklar.keys())
    
    sonuclar = {}
    
    for dork_key in secilen_dorklar:
        if dork_key in tum_dorklar:
            dork_bilgisi = tum_dorklar[dork_key]
            aciklama = dork_bilgisi["aciklama"]
            dork = dork_bilgisi["sorgu"]
            
            print(f"\n[{aciklama}]")
            sonuclar[aciklama] = []
            
            try:
                for url in search(dork, num_results=num_results, lang="tr"):
                    print(f"🔗 {url}")
                    sonuclar[aciklama].append(url)
            except Exception as e:
                hata_mesaji = f"[!] Hata: {e}"
                print(hata_mesaji)
                sonuclar[aciklama].append(hata_mesaji)
    
    return sonuclar

def ozel_dork_ara(domain, ozel_dork, num_results=5):

    tam_sorgu = f"site:{domain} {ozel_dork}"
    print(f"\n[ÖZEL DORK: {tam_sorgu}]")
    
    sonuclar = []
    
    try:
        for url in search(tam_sorgu, num_results=num_results, lang="tr"):
            print(f"🔗 {url}")
            sonuclar.append(url)
    except Exception as e:
        hata_mesaji = f"[!] Hata: {e}"
        print(hata_mesaji)
        sonuclar.append(hata_mesaji)
    
    return sonuclar

if __name__ == '__main__':
    dork_ara("mu.edu.tr")