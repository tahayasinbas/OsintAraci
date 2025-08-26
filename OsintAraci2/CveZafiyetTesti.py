import requests
import json
import re
from datetime import datetime

def nvd_search_cves(api_key=None, **params):

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    
    date_params = ['pubStartDate', 'pubEndDate', 'modStartDate', 'modEndDate']
    for param in date_params:
        if param in params and params[param]:
            if re.match(r'^\d{4}-\d{2}-\d{2}$', params[param]):
                params[param] = f"{params[param]}T00:00:00.000Z"
    
    print(f"[+] NVD API'sine sorgu yapılıyor...")
    print(f"    Parametreler: {params}")
    
    try:
        response = requests.get(base_url, params=params, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            
            total_results = data.get("totalResults", 0)
            print(f"[+] Toplam {total_results} zafiyet bulundu.")
            
            for vuln in data.get("vulnerabilities", []):
                cve_info = vuln["cve"]
                cve_id = cve_info["id"]
                
                description = "Açıklama bulunamadı."
                for desc in cve_info.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                severity = "Belirlenmemiş"
                cvss_score = None
                
                metrics = cve_info.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    base_metric = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = base_metric.get("baseSeverity", "Belirlenmemiş")
                    cvss_score = base_metric.get("baseScore", None)
                elif "cvssMetricV2" in metrics:
                    base_metric = metrics["cvssMetricV2"][0]["cvssData"] 
                    severity = base_metric.get("baseSeverity", "Belirlenmemiş")
                    cvss_score = base_metric.get("baseScore", None)
                
                published_date = cve_info.get("published", "")
                if published_date:
                    published_date = published_date.split("T")[0]
                
                last_modified = cve_info.get("lastModified", "")
                if last_modified:
                    last_modified = last_modified.split("T")[0]
                
                affected_products = []
                if "configurations" in cve_info:
                    for config in cve_info["configurations"]:
                        for node in config.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                if cpe_match.get("vulnerable", False):
                                    affected_products.append(cpe_match.get("criteria", ""))
                
                vulnerability = {
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "published_date": published_date,
                    "last_modified": last_modified,
                    "affected_products": affected_products[:10] if affected_products else []  # İlk 10 ürün
                }
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
        else:
            print(f"[!] Hata: HTTP {response.status_code}")
            print(f"    Yanıt: {response.text}")
            return []
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def build_nvd_query_params(options):
    params = {}
    
    if options.get('use_keyword') and options.get('keyword'):
        params['keywordSearch'] = options['keyword']
    
    if options.get('use_cpe') and options.get('cpe'):
        params['cpeName'] = options['cpe']
    
    if options.get('use_cve_id') and options.get('cve_id'):
        cve_id = options['cve_id']
        if not cve_id.startswith('CVE-'):
            cve_id = f"CVE-{cve_id}"
        params['cveId'] = cve_id
    
    if options.get('use_pub_date'):
        if options.get('pub_start_date'):
            params['pubStartDate'] = options['pub_start_date']
        if options.get('pub_end_date'):
            params['pubEndDate'] = options['pub_end_date']
    
    if options.get('use_mod_date'):
        if options.get('mod_start_date'):
            params['modStartDate'] = options['mod_start_date']
        if options.get('mod_end_date'):
            params['modEndDate'] = options['mod_end_date']
    
    if options.get('use_cvss') and options.get('cvss_severity'):
        params['cvssV3Severity'] = options['cvss_severity']
    
    if options.get('results_per_page'):
        params['resultsPerPage'] = options['results_per_page']
    if options.get('start_index'):
        params['startIndex'] = options['start_index']
    
    return params

if __name__ == "__main__":
    print("CVE Zafiyet Testi Aracı")
    print("------------------------")
    
    api_key = input("NVD API anahtarı (varsa): ").strip() or None
    
    print("\nArama seçenekleri:")
    print("1. Anahtar kelime ile ara")
    print("2. CPE adı ile ara")
    print("3. CVE ID ile ara")
    print("4. Yayın tarihine göre ara")
    print("5. CVSS şiddetine göre ara")
    
    choice = input("\nSeçiminiz (1-5): ")
    
    options = {}
    
    if choice == "1":
        keyword = input("Anahtar kelime: ")
        options = {
            'use_keyword': True,
            'keyword': keyword,
            'results_per_page': 10
        }
    
    elif choice == "2":
        cpe = input("CPE adı (örn: cpe:/a:apache:http_server:2.4.49): ")
        options = {
            'use_cpe': True,
            'cpe': cpe,
            'results_per_page': 10
        }
    
    elif choice == "3":
        cve_id = input("CVE ID (örn: CVE-2021-41773): ")
        options = {
            'use_cve_id': True,
            'cve_id': cve_id,
            'results_per_page': 10
        }
    
    elif choice == "4":
        start_date = input("Başlangıç tarihi (YYYY-MM-DD): ")
        end_date = input("Bitiş tarihi (YYYY-MM-DD): ")
        options = {
            'use_pub_date': True,
            'pub_start_date': start_date,
            'pub_end_date': end_date,
            'results_per_page': 10
        }
    
    elif choice == "5":
        severity = input("CVSS şiddeti (LOW, MEDIUM, HIGH, CRITICAL): ").upper()
        options = {
            'use_cvss': True,
            'cvss_severity': severity,
            'results_per_page': 10
        }
    
    else:
        print("Geçersiz seçim!")
        exit()
    
    params = build_nvd_query_params(options)
    
    vulnerabilities = nvd_search_cves(api_key=api_key, **params)
    
    if vulnerabilities:
        print(f"\n{len(vulnerabilities)} zafiyet bulundu:\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln['cve_id']} - Şiddet: {vuln['severity']} (CVSS: {vuln['cvss_score']})")
            print(f"   Yayın Tarihi: {vuln['published_date']}")
            print(f"   Açıklama: {vuln['description'][:150]}...")
            
            if vuln['affected_products']:
                print(f"   Etkilenen Ürünler: {', '.join(vuln['affected_products'][:3])}")
                if len(vuln['affected_products']) > 3:
                    print(f"   ... ve {len(vuln['affected_products'])-3} ürün daha")
            
            print()
    else:
        print("\nZafiyet bulunamadı veya arama hatası oluştu.")
    