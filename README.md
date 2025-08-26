# OsintAraci

## English
A Python-based OSINT and basic vulnerability/certificate analysis toolkit with a modern Tkinter GUI. It brings together whois/DNS lookups, passive SSL certificate fetching, Google dorking, NVD CVE search, basic SYN port scanning (Scapy), and a Scrapy crawler for KVKK data breach announcements. The main GUI is in `Arayuz.py`.

### Features
- Whois lookup and DNS records retrieval (`WhoisDns.py`)
- Server info, basic SYN port scan (Scapy), and simple OS/service detection
- Passive SSL certificate information via crt.sh (`ssl_kontrolpasif.py`)
- Google dork searches and custom dorks (`googledorks.py`)
- NVD API based CVE search and filtering (`CveZafiyetTesti.py`)
- Scrapy-based crawler for KVKK breach announcements and post-processing (`KvkkVeriIhlali/`)
- Tkinter GUI with `ttkthemes` and `ttkwidgets`

### Screenshots
Add your images into a folder like `assets/` or `docs/images/` and update the paths below. Recommended width ~800px.

1) Tab 1 — Overview/Dashboard

<img width="638" height="412" alt="1" src="https://github.com/user-attachments/assets/4c742bbf-6e9b-466b-914f-ffc1c6e90fa3" />


2) Tab 2 — Whois & DNS
<img width="629" height="409" alt="2" src="https://github.com/user-attachments/assets/1062f64b-ee06-4c66-9217-03bf6ba1eb50" />


3) Tab 3 — SSL (crt.sh)  
<img width="641" height="415" alt="3" src="https://github.com/user-attachments/assets/4229f06f-19bd-49c3-940c-f362b800b850" />


4) Tab 4 — Google Dorks  
<img width="637" height="414" alt="4" src="https://github.com/user-attachments/assets/aeb22ff4-6dca-45c3-945f-21e6f8e3892e" />


5) Tab 5 — CVE (NVD)  
<img width="639" height="412" alt="5" src="https://github.com/user-attachments/assets/742b2ceb-7cbd-497e-a3e7-091a29bb64f5" />


6) Tab 6 — KVKK Crawler  
<img width="641" height="413" alt="6" src="https://github.com/user-attachments/assets/d97238b8-99b7-4c32-8d3c-1dddc4248298" />


### Project Structure
```
OsintAraci/
├─ Arayuz.py                    # Main GUI application
├─ WhoisDns.py                  # Whois, DNS, SYN port scan, OS/service detection
├─ ssl_kontrolpasif.py          # Passive SSL info via crt.sh
├─ CveZafiyetTesti.py           # NVD CVE search helpers
├─ googledorks.py               # Google dork searches
├─ KvkkVeriIhlali/
│  └─ vericrawler/
│     ├─ Veritemizleme.py       # KVKK data cleaning/analysis helpers
│     ├─ scrapy.cfg
│     └─ vericrawler/
│        ├─ settings.py
│        ├─ items.py
│        ├─ pipelines.py
│        └─ spiders/
│           └─ SearchCrawler.py # KVKK announcement crawler
└─ requirements.txt
```

### Requirements
- Python 3.10+ (tested on Windows)
- Python packages (see `requirements.txt`):
  - requests, urllib3, whois, dnspython, scapy, Pillow, scrapy, itemadapter,
    googlesearch-python, ttkthemes, ttkwidgets
- For Windows networking (SYN scan):
  - Install Npcap: https://nmap.org/npcap/
  - You may need to run your terminal/IDE as Administrator.

### Installation
1) Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/OsintAraci.git
   cd OsintAraci
   ```
2) Create a virtual environment (recommended):
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/macOS
   ```
3) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage
- Start the GUI:
  ```bash
  python Arayuz.py
  ```
- Through the interface you can:
  - Perform whois and DNS queries
  - Run basic SYN-based port scans and simple OS/service detection
  - Fetch passive SSL certificate data via crt.sh
  - Execute Google dork searches
  - Search CVEs on NVD and filter results

#### KVKK Crawler
Located under `KvkkVeriIhlali/vericrawler`.
- Example:
  ```bash
  cd KvkkVeriIhlali/vericrawler
  scrapy crawl searchcrawler -O output.json
  ```
- Use functions in `Veritemizleme.py` to clean/analyze collected data.

### Notes
- Scapy-based SYN scans may require additional privileges or firewall adjustments.
- DNS/Whois queries depend on network conditions and may vary.
- GUI uses `ttkthemes` and `ttkwidgets` for theming and autocomplete.

---

## Türkçe
Python ile geliştirilmiş, modern bir Tkinter arayüzüne sahip OSINT ve temel zafiyet/sertifika analiz aracıdır. Whois/DNS sorguları, pasif SSL sertifika bilgisi çekme, Google dork aramaları, NVD üzerinden CVE arama, temel SYN port taraması (Scapy) ve KVKK veri ihlali duyuruları için Scrapy tabanlı bir tarayıcıyı bir araya getirir. Ana arayüz `Arayuz.py` içindedir.

### Özellikler
- Whois sorgulama ve DNS kayıtlarını çekme (`WhoisDns.py`)
- Sunucu bilgisi ve temel SYN port taraması (Scapy) + basit OS/servis tespiti
- Pasif SSL sertifika bilgisi çekme (crt.sh üzerinden) (`ssl_kontrolpasif.py`)
- Google dork aramaları ve özel dork desteği (`googledorks.py`)
- NVD API üzerinden CVE arama ve filtreleme (`CveZafiyetTesti.py`)
- KVKK veri ihlali duyurularını Scrapy ile tarama ve temizlik/analiz (`KvkkVeriIhlali/`)
- `ttkthemes` ve `ttkwidgets` ile modern Tkinter arayüz

### Ekran Görüntüleri
Görselleri `assets/` veya `docs/images/` gibi bir klasöre ekleyip aşağıdaki yolları güncelleyebilirsiniz. Önerilen genişlik ~800px.

1) Sekme 1 — Genel Bakış  
<img width="638" height="412" alt="1" src="https://github.com/user-attachments/assets/4d2673ce-ec29-4859-8d21-aaa689d63ea1" />


2) Sekme 2 — Whois & DNS  
<img width="629" height="409" alt="2" src="https://github.com/user-attachments/assets/05ecfabb-ecf0-4762-9134-4ebd1ddaacc3" />


3) Sekme 3 — SSL (crt.sh)  
<img width="641" height="415" alt="3" src="https://github.com/user-attachments/assets/358aff3e-7902-482a-892c-9f300d62f2ad" />


4) Sekme 4 — Google Dork  
<img width="637" height="414" alt="4" src="https://github.com/user-attachments/assets/84e8e9c0-7453-44f0-ac06-5b5749f04697" />


5) Sekme 5 — CVE (NVD)  
<img width="639" height="412" alt="5" src="https://github.com/user-attachments/assets/d08c1bad-d840-4cdd-97d8-a940d489e2f4" />


6) Sekme 6 — KVKK Tarayıcı  
<img width="641" height="413" alt="6" src="https://github.com/user-attachments/assets/182681de-6c9f-4c56-95da-e6fc5af3fb01" />


### Proje Yapısı
```
OsintAraci/
├─ Arayuz.py                    # Ana GUI uygulaması
├─ WhoisDns.py                  # Whois, DNS, SYN port tarama, OS/servis tespiti
├─ ssl_kontrolpasif.py          # crt.sh pasif SSL bilgi çekme ve çözümleme
├─ CveZafiyetTesti.py           # NVD CVE arama yardımcıları
├─ googledorks.py               # Google dork aramaları
├─ KvkkVeriIhlali/
│  └─ vericrawler/
│     ├─ Veritemizleme.py       # KVKK verisi temizleme/analiz yardımcıları
│     ├─ scrapy.cfg
│     └─ vericrawler/
│        ├─ settings.py
│        ├─ items.py
│        ├─ pipelines.py
│        └─ spiders/
│           └─ SearchCrawler.py # KVKK duyuru tarayıcısı
└─ requirements.txt
```

### Gereksinimler
- Python 3.10+ (Windows üzerinde test edildi)
- `requirements.txt` içindeki paketler:
  - requests, urllib3, whois, dnspython, scapy, Pillow, scrapy, itemadapter,
    googlesearch-python, ttkthemes, ttkwidgets
- Windows’ta ağ özellikleri (SYN tarama) için:
  - Npcap kurulumu: https://nmap.org/npcap/
  - Komut satırını/IDE’yi yönetici olarak çalıştırmanız gerekebilir.

### Kurulum
1) Depoyu klonlayın:
   ```bash
   git clone https://github.com/tahayasinbas/OsintAraci.git
   cd OsintAraci
   ```
2) Sanal ortam (önerilen):
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/macOS
   ```
3) Bağımlılıkları kurun:
   ```bash
   pip install -r requirements.txt
   ```

### Kullanım
- GUI’yi başlatmak için:
  ```bash
  python Arayuz.py
  ```
- Arayüz üzerinden:
  - Whois ve DNS sorguları yapabilir,
  - SYN tabanlı basit port taraması ve olası servis/OS tespiti çalıştırabilir,
  - crt.sh üzerinden pasif SSL sertifika bilgisi toplayabilir,
  - Google dork aramaları gerçekleştirebilir,
  - NVD üzerinde CVE arayabilir ve sonuçları filtreleyebilirsiniz.

#### KVKK Veri İhlali Tarayıcısı
`KvkkVeriIhlali/vericrawler` altında yer alır.
- Örnek:
  ```bash
  cd KvkkVeriIhlali/vericrawler
  scrapy crawl searchcrawler -O output.json
  ```
- Toplanan veriyi temizlemek/analiz etmek için `Veritemizleme.py` fonksiyonlarını kullanabilirsiniz.

### Notlar
- Scapy ile SYN taraması bazı sistemlerde ek izinler veya firewall ayarları gerektirebilir.
- DNS/Whois sorguları ağ koşullarına bağlı olarak gecikebilir veya farklı sonuçlar dönebilir.
- Arayüzdeki tema/otomatik tamamlama için `ttkthemes` ve `ttkwidgets` paketleri kullanılmaktadır.
