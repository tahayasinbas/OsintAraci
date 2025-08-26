import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from WhoisDns import whois_sorgula, dns_kayitlarini_al, get_server_info, syn_port_scan, detect_os_and_versions, detect_services_for_open_ports
import dns.resolver
import threading
from ttkthemes import ThemedTk
from ttkwidgets.autocomplete import AutocompleteEntry
import os
from PIL import Image, ImageTk
from datetime import datetime, timezone
from ssl_kontrolpasif import crtsh_ssl_bilgisi
from CveZafiyetTesti import nvd_search_cves, build_nvd_query_params
from googledorks import dork_ara, ozel_dork_ara
import subprocess
import re


COLORS = {
    "primary": "#1a365d",     # Koyu mavi
    "secondary": "#ff7900",   # Turuncu
    "success": "#39b54a",     # Yeşil
    "warning": "#f7bc16",     # Sarı
    "danger": "#d9534f",      # Kırmızı
    "light_bg": "#f5f5f7",    # Açık gri
    "medium_bg": "#e8e8e8",   # Orta gri
    "dark_bg": "#444444",     # Koyu gri
    "text": "#333333",        # Metin rengi
    "text_light": "#ffffff"   # Açık metin rengi
}


pencere = ThemedTk(theme="arc")
pencere.title("OSINT ZAFIYET ANALİZ ARACI TAHA YASIN BAS")
pencere.geometry("1280x800")
pencere.minsize(1000, 700)
pencere.configure(bg=COLORS["light_bg"])


try:

    logo_path = os.path.join(os.path.dirname(__file__), "icons", "logo.png")
    if os.path.exists(logo_path):
        logo = ImageTk.PhotoImage(Image.open(logo_path).resize((32, 32)))
        pencere.iconphoto(True, logo)
except:
    pass  


style = ttk.Style()
style.theme_use('clam')

style.configure("TFrame", background=COLORS["light_bg"])
style.configure("TLabel", background=COLORS["light_bg"], foreground=COLORS["text"], font=('Segoe UI', 10))
style.configure("TEntry", padding=6, relief="flat", borderwidth=1)
style.configure("TButton", padding=6, relief="flat", borderwidth=1, background=COLORS["primary"])

style.configure("TNotebook", background=COLORS["light_bg"], borderwidth=0, tabmargin=0)
style.configure("TNotebook.Tab", 
                background=COLORS["medium_bg"], 
                padding=[15, 8], 
                font=('Segoe UI', 10, 'bold'),
                borderwidth=0)
style.map("TNotebook.Tab",
          background=[("selected", COLORS["primary"])],
          foreground=[("selected", COLORS["text_light"])])

style.configure("Action.TButton", 
                font=('Segoe UI', 10, 'bold'),
                padding=8,
                background=COLORS["primary"],
                foreground=COLORS["text_light"])
style.map("Action.TButton",
          background=[("active", COLORS["secondary"])],
          foreground=[("active", COLORS["text_light"])])

    
style.configure("Success.TButton", 
                font=('Segoe UI', 10, 'bold'),
                padding=8,
                background=COLORS["success"],
                foreground=COLORS["text_light"])
style.map("Success.TButton",
          background=[("active", "#2d9d3c")],
          foreground=[("active", COLORS["text_light"])])

header_frame = ttk.Frame(pencere, style="Header.TFrame")
header_frame.pack(fill=tk.X, padx=0, pady=0)
style.configure("Header.TFrame", background=COLORS["primary"])
header_label = ttk.Label(header_frame, text="OSINT ZAFIYET ANALİZ ARACI TAHA YASIN BAS", font=('Segoe UI', 16, 'bold'),
                         foreground=COLORS["text_light"], background=COLORS["primary"])
header_label.pack(side=tk.LEFT, padx=15, pady=10)


style.configure("Card.TFrame", 
                background="white",
                relief=tk.RAISED,
                borderwidth=1)


main_notebook = ttk.Notebook(pencere)
main_notebook.pack(expand=True, fill="both", padx=10, pady=10)

tab_domain = ttk.Frame(main_notebook)
tab_vuln = ttk.Frame(main_notebook)
tab_ssl = ttk.Frame(main_notebook)
tab_dorks = ttk.Frame(main_notebook)
tab_breach = ttk.Frame(main_notebook)
tab_network = ttk.Frame(main_notebook)


main_notebook.add(tab_domain, text="🔍 Domain Bilgileri")
main_notebook.add(tab_vuln, text="🔥 Zafiyet Araştırması")
main_notebook.add(tab_ssl, text="🔒 SSL Güvenliği")
main_notebook.add(tab_dorks, text="🕸️ Google Dorks")
main_notebook.add(tab_breach, text="⚠️ Veri İhlali")
main_notebook.add(tab_network, text="🔌 Network Tarama")


status_frame = ttk.Frame(pencere, relief=tk.GROOVE, borderwidth=1)
status_frame.pack(side=tk.BOTTOM, fill=tk.X)

status_bar = ttk.Label(status_frame, text="Hazır", anchor=tk.W)
status_bar.pack(side=tk.LEFT, fill=tk.X, padx=10, pady=2)
progress = ttk.Progressbar(status_frame, mode='indeterminate', length=100)

def run_async(func, callback=None):
    def wrapper(*args, **kwargs):
        progress.pack(side=tk.RIGHT, padx=10, pady=2)
        progress.start()
        status_bar.config(text="İşlem çalışıyor...")
        
        result = func(*args, **kwargs)
        
        progress.stop()
        progress.pack_forget()
        status_bar.config(text="Hazır")
        
        if callback:
            callback(result)
    
    thread = threading.Thread(target=wrapper)
    thread.daemon = True
    thread.start()


def on_whois_double_click(event):
    _on_treeview_double_click(event, whois_treeview, "WHOIS Detayı")


def on_dns_double_click(event):
    _on_treeview_double_click(event, dns_treeview, "DNS Detayı")


def on_server_double_click(event):
    _on_treeview_double_click(event, server_treeview, "Server Detayı")


def _on_treeview_double_click(event, treeview, title_prefix):

    region = treeview.identify("region", event.x, event.y)
    if region != "cell":
        return

    row_id = treeview.identify_row(event.y)
    col_id = treeview.identify_column(event.x)
    if not row_id:
        return

    values = treeview.item(row_id, "values")
    prop = values[0] if len(values) > 1 else ""
    val = values[1] if len(values) > 1 else values[0]

    detay_win = tk.Toplevel()
    detay_win.title(f"{title_prefix}: {prop}")
    detay_win.geometry("400x300")

    text = tk.Text(detay_win, wrap="word")
    text.insert("1.0", val)
    text.config(state="disabled")
    text.pack(expand=True, fill="both", padx=10, pady=10)

    ttk.Button(detay_win, text="Kapat", command=detay_win.destroy).pack(pady=5)


tab_domain.columnconfigure(0, weight=1)
tab_domain.rowconfigure(0, weight=0)
tab_domain.rowconfigure(1, weight=1)

search_card = ttk.Frame(tab_domain, style="Card.TFrame")
search_card.grid(row=0, column=0, sticky="ew", padx=20, pady=10)

search_frame = ttk.Frame(search_card, padding=15)
search_frame.pack(fill="x")

ttk.Label(search_frame, text="Domain:", font=('Segoe UI', 11)).grid(row=0, column=0, padx=5, pady=10)
domain_entry = AutocompleteEntry(search_frame, width=40, font=('Segoe UI', 11), 
                                completevalues=[".com", ".net", ".org", ".edu.tr"])
domain_entry.grid(row=0, column=1, padx=5, pady=10)
button_frame = ttk.Frame(search_frame)
button_frame.grid(row=0, column=2, padx=10, pady=10)

whois_button = ttk.Button(button_frame, text="WHOIS", style="Action.TButton")
whois_button.pack(side=tk.LEFT, padx=5)

dns_button = ttk.Button(button_frame, text="DNS", style="Action.TButton")
dns_button.pack(side=tk.LEFT, padx=5)

server_button = ttk.Button(button_frame, text="Server Info", style="Action.TButton")
server_button.pack(side=tk.LEFT, padx=5)

content_card = ttk.Frame(tab_domain, style="Card.TFrame")
content_card.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)

result_notebook = ttk.Notebook(content_card)
result_notebook.pack(expand=True, fill="both", padx=5, pady=5)

whois_frame = ttk.Frame(result_notebook)
result_notebook.add(whois_frame, text="WHOIS Bilgileri")

whois_y_scrollbar = ttk.Scrollbar(whois_frame, orient="vertical")
whois_y_scrollbar.pack(side="right", fill="y")

whois_x_scrollbar = ttk.Scrollbar(whois_frame, orient="horizontal")
whois_x_scrollbar.pack(side="bottom", fill="x")

whois_treeview = ttk.Treeview(
    whois_frame, 
    columns=("Özellik", "Değer"), 
    show="headings",
    yscrollcommand=whois_y_scrollbar.set,
    xscrollcommand=whois_x_scrollbar.set
)

whois_y_scrollbar.config(command=whois_treeview.yview)
whois_x_scrollbar.config(command=whois_treeview.xview)
whois_treeview.pack(fill="both", expand=True)

whois_treeview.column("Özellik", width=200, minwidth=150)
whois_treeview.column("Değer", width=600, minwidth=400)
whois_treeview.heading("Özellik", text="Özellik")
whois_treeview.heading("Değer", text="Değer")

whois_treeview.tag_configure('oddrow', background='#f9f9f9')
whois_treeview.tag_configure('evenrow', background='white')

whois_treeview.bind("<Double-1>", on_whois_double_click)
dns_frame = ttk.Frame(result_notebook)
result_notebook.add(dns_frame, text="DNS Kayıtları")

dns_y_scrollbar = ttk.Scrollbar(dns_frame, orient="vertical")
dns_y_scrollbar.pack(side="right", fill="y")

dns_x_scrollbar = ttk.Scrollbar(dns_frame, orient="horizontal")
dns_x_scrollbar.pack(side="bottom", fill="x")

dns_treeview = ttk.Treeview(
    dns_frame, 
    columns=("Kayıt Türü", "Değer"), 
    show="headings",
    yscrollcommand=dns_y_scrollbar.set,
    xscrollcommand=dns_x_scrollbar.set
)

dns_y_scrollbar.config(command=dns_treeview.yview)
dns_x_scrollbar.config(command=dns_treeview.xview)
dns_treeview.pack(fill="both", expand=True)

dns_treeview.column("Kayıt Türü", width=200, minwidth=150)
dns_treeview.column("Değer", width=600, minwidth=400)
dns_treeview.heading("Kayıt Türü", text="Kayıt Türü")
dns_treeview.heading("Değer", text="Değer")

dns_treeview.tag_configure('oddrow', background='#f9f9f9')
dns_treeview.tag_configure('evenrow', background='white')

dns_treeview.bind("<Double-1>",   on_dns_double_click)
server_frame = ttk.Frame(result_notebook)
result_notebook.add(server_frame, text="Server Bilgileri")

server_y_scrollbar = ttk.Scrollbar(server_frame, orient="vertical")
server_y_scrollbar.pack(side="right", fill="y")

server_x_scrollbar = ttk.Scrollbar(server_frame, orient="horizontal")
server_x_scrollbar.pack(side="bottom", fill="x")

server_treeview = ttk.Treeview(
    server_frame, 
    columns=("Özellik", "Değer"), 
    show="headings",
    yscrollcommand=server_y_scrollbar.set,
    xscrollcommand=server_x_scrollbar.set
)

server_y_scrollbar.config(command=server_treeview.yview)
server_x_scrollbar.config(command=server_treeview.xview)
server_treeview.pack(fill="both", expand=True)

server_treeview.column("Özellik", width=200, minwidth=150)
server_treeview.column("Değer", width=600, minwidth=400)
server_treeview.heading("Özellik", text="Özellik")
server_treeview.heading("Değer", text="Değer")

server_treeview.tag_configure('oddrow', background='#f9f9f9')
server_treeview.tag_configure('evenrow', background='white')

server_treeview.bind("<Double-1>", on_server_double_click)


def whois_tikla():
    domain = domain_entry.get()
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin.")
        return

    def whois_callback(bilgi):
        whois_treeview.delete(*whois_treeview.get_children())

        if bilgi:
            row_properties = list(bilgi.keys())
            for i, prop in enumerate(row_properties):
                value = bilgi[prop]
                tag = 'evenrow' if i % 2 == 0 else 'oddrow'

                if isinstance(value, list):
                    value = '\n'.join(str(item) for item in value)
                elif value is None:
                    value = "Bilgi Yok"

                whois_treeview.insert("", "end", values=(prop, value), tags=(tag,))

            result_notebook.select(0)  
        else:
            messagebox.showerror("Hata", f"{domain} için WHOIS bilgileri alınamadı.")

    run_async(lambda: whois_sorgula(domain), whois_callback)

def dns_tikla():
    domain = domain_entry.get()
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin.")
        return
    
    def dns_callback(bilgi):
        dns_treeview.delete(*dns_treeview.get_children())
        
        if bilgi:
            row_count = 0
            for kayit_turu, kayitlar in bilgi.items():
                for kayit in kayitlar:
                    tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                    dns_treeview.insert("", "end", values=(kayit_turu, kayit), tags=(tag,))
                    row_count += 1
            
            result_notebook.select(1) 
        else:
            messagebox.showerror("Hata", f"{domain} için DNS kayıtları alınamadı.")
    
    run_async(lambda: dns_kayitlarini_al(domain), dns_callback)

def server_tikla():
    domain = domain_entry.get()
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin.")
        return
    
    def server_callback(bilgi):
        server_treeview.delete(*server_treeview.get_children())
        
        if bilgi and not 'error' in bilgi:
            row_count = 0

            for key, value in bilgi.items():
                if key != 'headers':
                    tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                    server_treeview.insert("", "end", values=(key, value), tags=(tag,))
                    row_count += 1
            
            if 'headers' in bilgi:
                for key, value in bilgi['headers'].items():
                    tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                    server_treeview.insert("", "end", values=(f"Header: {key}", value), tags=(tag,))
                    row_count += 1
            
            result_notebook.select(2) 
        else:
            messagebox.showerror("Hata", f"{domain} için sunucu bilgileri alınamadı: {bilgi.get('error', 'Bilinmeyen hata')}")
    
    run_async(lambda: get_server_info(domain), server_callback)

whois_button.config(command=whois_tikla)
dns_button.config(command=dns_tikla)
server_button.config(command=server_tikla)

vuln_main_frame = ttk.Frame(tab_vuln)
vuln_main_frame.pack(fill="both", expand=True, padx=10, pady=10)

vuln_search_card = ttk.Frame(vuln_main_frame, style="Card.TFrame")
vuln_search_card.pack(fill="x", padx=10, pady=10)

vuln_search_frame = ttk.Frame(vuln_search_card, padding=15)
vuln_search_frame.pack(fill="x")

ttk.Label(vuln_search_frame, text="📋 Arama Türü:", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w", padx=5, pady=10)

search_type_var = tk.StringVar(value="keyword")

search_type_frame = ttk.Frame(vuln_search_frame)
search_type_frame.grid(row=0, column=1, columnspan=3, sticky="w", padx=5, pady=5)

ttk.Radiobutton(search_type_frame, text="Anahtar Kelime", variable=search_type_var, value="keyword").pack(side=tk.LEFT, padx=10)
ttk.Radiobutton(search_type_frame, text="CPE", variable=search_type_var, value="cpe").pack(side=tk.LEFT, padx=10)
ttk.Radiobutton(search_type_frame, text="CVE ID", variable=search_type_var, value="cve_id").pack(side=tk.LEFT, padx=10)
ttk.Radiobutton(search_type_frame, text="Tarih Aralığı", variable=search_type_var, value="date").pack(side=tk.LEFT, padx=10)
ttk.Radiobutton(search_type_frame, text="CVSS Şiddeti", variable=search_type_var, value="cvss").pack(side=tk.LEFT, padx=10)

ttk.Label(vuln_search_frame, text="🔍 Arama Değeri:", font=("Segoe UI", 11, "bold")).grid(row=1, column=0, sticky="w", padx=5, pady=10)
search_value_entry = ttk.Entry(vuln_search_frame, width=40, font=('Segoe UI', 11))
search_value_entry.grid(row=1, column=1, columnspan=3, sticky="w", padx=5, pady=10)
ttk.Label(vuln_search_frame, text="⚙️ Gelişmiş Filtreler:", font=("Segoe UI", 11, "bold")).grid(row=2, column=0, sticky="w", padx=5, pady=10)
advanced_filters_frame = ttk.Frame(vuln_search_frame)
advanced_filters_frame.grid(row=2, column=1, columnspan=3, sticky="w", padx=5, pady=5)
ttk.Label(advanced_filters_frame, text="CVSS Şiddeti:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
cvss_values = ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
cvss_severity_combo = ttk.Combobox(advanced_filters_frame, values=cvss_values, width=10, state="readonly")
cvss_severity_combo.current(0)
cvss_severity_combo.grid(row=0, column=1, sticky="w", padx=5, pady=5)
ttk.Label(advanced_filters_frame, text="Başlangıç:").grid(row=0, column=2, sticky="w", padx=(15, 5), pady=5)
start_date_entry = ttk.Entry(advanced_filters_frame, width=12)
start_date_entry.grid(row=0, column=3, sticky="w", padx=5, pady=5)
start_date_entry.insert(0, "YYYY-MM-DD")

ttk.Label(advanced_filters_frame, text="Bitiş:").grid(row=0, column=4, sticky="w", padx=(15, 5), pady=5)
end_date_entry = ttk.Entry(advanced_filters_frame, width=12)
end_date_entry.grid(row=0, column=5, sticky="w", padx=5, pady=5)
end_date_entry.insert(0, "YYYY-MM-DD")
ttk.Label(advanced_filters_frame, text="Sayfa Başına:").grid(row=0, column=6, sticky="w", padx=(15, 5), pady=5)
results_per_page_values = ["5", "10", "20", "50"]
results_per_page_combo = ttk.Combobox(advanced_filters_frame, values=results_per_page_values, width=5, state="readonly")
results_per_page_combo.current(1)  # Varsayılan 10
results_per_page_combo.grid(row=0, column=7, sticky="w", padx=5, pady=5)
ttk.Label(vuln_search_frame, text="🔐 API Anahtarı:", font=("Segoe UI", 11, "bold")).grid(row=3, column=0, sticky="w", padx=5, pady=10)
api_key_entry = ttk.Entry(vuln_search_frame, width=40, font=('Segoe UI', 11))
api_key_entry.grid(row=3, column=1, columnspan=3, sticky="w", padx=5, pady=10)
vuln_button_frame = ttk.Frame(vuln_search_frame)
vuln_button_frame.grid(row=4, column=0, columnspan=4, pady=10)

search_vuln_button = ttk.Button(vuln_button_frame, text="ARA", style="Action.TButton", width=15)
search_vuln_button.pack(side=tk.LEFT, padx=10)

clear_vuln_button = ttk.Button(vuln_button_frame, text="TEMİZLE", width=15)
clear_vuln_button.pack(side=tk.LEFT, padx=10)

vuln_results_card = ttk.Frame(vuln_main_frame, style="Card.TFrame")
vuln_results_card.pack(fill="both", expand=True, padx=10, pady=10)
vuln_results_header = ttk.Frame(vuln_results_card, padding=10)
vuln_results_header.pack(fill="x")

vuln_count_label = ttk.Label(vuln_results_header, text="Toplam: 0 zafiyet | Sayfa: 0/0", font=("Segoe UI", 10))
vuln_count_label.pack(side=tk.LEFT)

vuln_table_frame = ttk.Frame(vuln_results_card, padding=10)
vuln_table_frame.pack(fill="both", expand=True)

vuln_table_container = ttk.Frame(vuln_table_frame)
vuln_table_container.pack(fill="both", expand=True)

vuln_y_scrollbar = ttk.Scrollbar(vuln_table_container, orient="vertical")
vuln_y_scrollbar.pack(side="right", fill="y")

vuln_x_scrollbar = ttk.Scrollbar(vuln_table_container, orient="horizontal")
vuln_x_scrollbar.pack(side="bottom", fill="x")

# Treeview oluşturma
vuln_treeview = ttk.Treeview(
    vuln_table_container,
    columns=("CVE ID", "Şiddet", "CVSS", "Yayın Tarihi", "Detay"),
    show="headings",
    yscrollcommand=vuln_y_scrollbar.set,
    xscrollcommand=vuln_x_scrollbar.set
)

vuln_y_scrollbar.config(command=vuln_treeview.yview)
vuln_x_scrollbar.config(command=vuln_treeview.xview)
vuln_treeview.pack(fill="both", expand=True)

# Sütun yapılandırması
vuln_treeview.column("CVE ID", width=150, minwidth=150)
vuln_treeview.column("Şiddet", width=100, minwidth=100)
vuln_treeview.column("CVSS", width=80, minwidth=80)
vuln_treeview.column("Yayın Tarihi", width=120, minwidth=120)
vuln_treeview.column("Detay", width=80, minwidth=80, anchor="center")

vuln_treeview.heading("CVE ID", text="CVE ID")
vuln_treeview.heading("Şiddet", text="Şiddet")
vuln_treeview.heading("CVSS", text="CVSS")
vuln_treeview.heading("Yayın Tarihi", text="Yayın Tarihi")
vuln_treeview.heading("Detay", text="Detay")

# Zebra desenli satırlar için tag'ler ve şiddet seviyeleri için renkler
vuln_treeview.tag_configure('oddrow', background='#f9f9f9')
vuln_treeview.tag_configure('evenrow', background='white')
vuln_treeview.tag_configure('critical', foreground='#e74c3c')
vuln_treeview.tag_configure('high', foreground='#e67e22')
vuln_treeview.tag_configure('medium', foreground='#f1c40f')
vuln_treeview.tag_configure('low', foreground='#2ecc71')
vuln_treeview.tag_configure('none', foreground='#95a5a6')

# Zafiyet Detayları bölümü
vuln_details_frame = ttk.LabelFrame(vuln_results_card, text="Zafiyet Detayları")
vuln_details_frame.pack(fill="x", padx=10, pady=10)

# Detay içeriği için iç çerçeve
vuln_details_content = ttk.Frame(vuln_details_frame, padding=10)
vuln_details_content.pack(fill="x", expand=True)

# Temel bilgi alanı
vuln_basic_info_frame = ttk.Frame(vuln_details_content)
vuln_basic_info_frame.pack(fill="x", pady=5)

# İlk satır: CVE ID ve Şiddet
vuln_cve_label = ttk.Label(vuln_basic_info_frame, text="📌 CVE-ID:", font=("Segoe UI", 11, "bold"))
vuln_cve_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
vuln_cve_value = ttk.Label(vuln_basic_info_frame, text="-", font=("Segoe UI", 11))
vuln_cve_value.grid(row=0, column=1, sticky="w", padx=5, pady=5)

vuln_severity_label = ttk.Label(vuln_basic_info_frame, text="⚠️ Şiddet:", font=("Segoe UI", 11, "bold"))
vuln_severity_label.grid(row=0, column=2, sticky="w", padx=(20, 5), pady=5)
vuln_severity_value = ttk.Label(vuln_basic_info_frame, text="-", font=("Segoe UI", 11))
vuln_severity_value.grid(row=0, column=3, sticky="w", padx=5, pady=5)

# İkinci satır: Yayın ve Güncelleme tarihleri
vuln_published_label = ttk.Label(vuln_basic_info_frame, text="📅 Yayın:", font=("Segoe UI", 11, "bold"))
vuln_published_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
vuln_published_value = ttk.Label(vuln_basic_info_frame, text="-", font=("Segoe UI", 11))
vuln_published_value.grid(row=1, column=1, sticky="w", padx=5, pady=5)

vuln_modified_label = ttk.Label(vuln_basic_info_frame, text="🔄 Güncelleme:", font=("Segoe UI", 11, "bold"))
vuln_modified_label.grid(row=1, column=2, sticky="w", padx=(20, 5), pady=5)
vuln_modified_value = ttk.Label(vuln_basic_info_frame, text="-", font=("Segoe UI", 11))
vuln_modified_value.grid(row=1, column=3, sticky="w", padx=5, pady=5)

# Açıklama alanı
vuln_desc_frame = ttk.Frame(vuln_details_content)
vuln_desc_frame.pack(fill="x", pady=10)

ttk.Label(vuln_desc_frame, text="📝 Açıklama:", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 5))
vuln_desc_text = tk.Text(vuln_desc_frame, wrap="word", height=4, font=("Segoe UI", 10))
vuln_desc_text.pack(fill="x")
vuln_desc_text.insert("1.0", "Zafiyet seçildiğinde açıklama burada görüntülenecek.")
vuln_desc_text.config(state="disabled")

# Etkilenen ürünler alanı
vuln_products_frame = ttk.Frame(vuln_details_content)
vuln_products_frame.pack(fill="x", pady=5)

ttk.Label(vuln_products_frame, text="🖥️ Etkilenen Ürünler:", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 5))
vuln_products_text = tk.Text(vuln_products_frame, wrap="word", height=3, font=("Segoe UI", 10))
vuln_products_text.pack(fill="x")
vuln_products_text.insert("1.0", "Zafiyet seçildiğinde etkilenen ürünler burada listelenecek.")
vuln_products_text.config(state="disabled")

# Butonlar
vuln_action_frame = ttk.Frame(vuln_details_content)
vuln_action_frame.pack(fill="x", pady=10)

export_vuln_button = ttk.Button(vuln_action_frame, text="DIŞA AKTAR", width=15)
export_vuln_button.pack(side=tk.LEFT, padx=5)

refs_vuln_button = ttk.Button(vuln_action_frame, text="REFERANSLAR", width=15)
refs_vuln_button.pack(side=tk.LEFT, padx=5)

exploit_vuln_button = ttk.Button(vuln_action_frame, text="EXPLOIT KONTROLÜ", width=20)
exploit_vuln_button.pack(side=tk.LEFT, padx=5)

# Sayfalama kontrolü
vuln_pagination_frame = ttk.Frame(vuln_results_card, padding=10)
vuln_pagination_frame.pack(fill="x")

prev_page_button = ttk.Button(vuln_pagination_frame, text="◀️ Önceki Sayfa", state="disabled")
prev_page_button.pack(side=tk.LEFT, padx=5)

page_info_label = ttk.Label(vuln_pagination_frame, text="Sayfa: 0/0")
page_info_label.pack(side=tk.LEFT, padx=20)

next_page_button = ttk.Button(vuln_pagination_frame, text="Sonraki Sayfa ▶️", state="disabled")
next_page_button.pack(side=tk.LEFT, padx=5)

# Fonksiyonlar
# Arama formunu temizleme
def clear_vuln_form():
    search_value_entry.delete(0, tk.END)
    api_key_entry.delete(0, tk.END)
    cvss_severity_combo.current(0)
    start_date_entry.delete(0, tk.END)
    start_date_entry.insert(0, "YYYY-MM-DD")
    end_date_entry.delete(0, tk.END)
    end_date_entry.insert(0, "YYYY-MM-DD")
    search_type_var.set("keyword")
    results_per_page_combo.current(1)
    vuln_treeview.delete(*vuln_treeview.get_children())
    vuln_count_label.config(text="Toplam: 0 zafiyet | Sayfa: 0/0")
    page_info_label.config(text="Sayfa: 0/0")
    
    # Detay alanlarını temizle
    vuln_cve_value.config(text="-")
    vuln_severity_value.config(text="-")
    vuln_published_value.config(text="-")
    vuln_modified_value.config(text="-")
    
    vuln_desc_text.config(state="normal")
    vuln_desc_text.delete("1.0", tk.END)
    vuln_desc_text.insert("1.0", "Zafiyet seçildiğinde açıklama burada görüntülenecek.")
    vuln_desc_text.config(state="disabled")
    
    vuln_products_text.config(state="normal")
    vuln_products_text.delete("1.0", tk.END)
    vuln_products_text.insert("1.0", "Zafiyet seçildiğinde etkilenen ürünler burada listelenecek.")
    vuln_products_text.config(state="disabled")

    prev_page_button.config(state="disabled")
    next_page_button.config(state="disabled")

# Zafiyet detaylarını gösterme fonksiyonu
def show_vuln_details(event):
    selected_item = vuln_treeview.selection()
    if not selected_item:
        return
    
    # Seçilen öğenin zafiyet bilgilerini al
    item = selected_item[0]
    values = vuln_treeview.item(item, "values")
    
    if not values:
        return
    
    # Seçilen CVE ID'sini bul
    cve_id = values[0]
    
    # Global zafiyet listesinden detayları bul
    selected_vuln = None
    for vuln in current_vulnerabilities:
        if vuln.get("cve_id") == cve_id:
            selected_vuln = vuln
            break
    
    if not selected_vuln:
        messagebox.showinfo("Bilgi", "Zafiyet detayları bulunamadı.")
        return
    
    # Detay alanlarını güncelle
    vuln_cve_value.config(text=selected_vuln.get("cve_id", "-"))
    
    # Şiddet değerine göre renk ve metin ayarla
    severity = selected_vuln.get("severity", "Belirlenmemiş")
    cvss_score = selected_vuln.get("cvss_score", "-")
    severity_text = f"{severity} (CVSS: {cvss_score})"
    vuln_severity_value.config(text=severity_text)
    
    if "CRITICAL" in severity.upper():
        vuln_severity_value.config(foreground="#e74c3c")
    elif "HIGH" in severity.upper():
        vuln_severity_value.config(foreground="#e67e22")
    elif "MEDIUM" in severity.upper():
        vuln_severity_value.config(foreground="#f1c40f")
    elif "LOW" in severity.upper():
        vuln_severity_value.config(foreground="#2ecc71")
    else:
        vuln_severity_value.config(foreground="#95a5a6")
    
    vuln_published_value.config(text=selected_vuln.get("published_date", "-"))
    vuln_modified_value.config(text=selected_vuln.get("last_modified", "-"))
    
    # Gerçek açıklama ve ürün bilgilerini doldur
    description = selected_vuln.get("description", "Açıklama bulunamadı.")
    affected_products = selected_vuln.get("affected_products", [])
    
    vuln_desc_text.config(state="normal")
    vuln_desc_text.delete("1.0", tk.END)
    vuln_desc_text.insert("1.0", description)
    vuln_desc_text.config(state="disabled")
    
    vuln_products_text.config(state="normal")
    vuln_products_text.delete("1.0", tk.END)
    if affected_products:
        for product in affected_products:
            vuln_products_text.insert(tk.END, f"• {product}\n")
    else:
        vuln_products_text.insert("1.0", "Etkilenen ürün bilgisi bulunamadı.")
    vuln_products_text.config(state="disabled")

# TreeView'a çift tıklama eventi
vuln_treeview.bind("<Double-1>", show_vuln_details)

# Zafiyet arama fonksiyonu
def search_vulnerabilities():
    # Mevcut sonuçları temizle
    vuln_treeview.delete(*vuln_treeview.get_children())
    
    # Arama parametrelerini al
    search_type = search_type_var.get()
    search_value = search_value_entry.get().strip()
    api_key = api_key_entry.get().strip() or None
    cvss_severity = cvss_severity_combo.get()
    start_date = start_date_entry.get()
    end_date = end_date_entry.get()
    results_per_page = int(results_per_page_combo.get())
    
    # Basit doğrulama
    if not search_value and search_type not in ['date', 'cvss']:
        messagebox.showwarning("Uyarı", "Lütfen arama değeri girin.")
        return
    
    # Arama parametrelerini yapılandır
    options = {
        'results_per_page': results_per_page,
        'start_index': 0
    }
    
    # Arama türüne göre parametreleri ayarla
    if search_type == "keyword":
        options['use_keyword'] = True
        options['keyword'] = search_value
    elif search_type == "cpe":
        options['use_cpe'] = True
        options['cpe'] = search_value
    elif search_type == "cve_id":
        options['use_cve_id'] = True
        options['cve_id'] = search_value
    elif search_type == "date":
        if start_date == "YYYY-MM-DD" or end_date == "YYYY-MM-DD":
            messagebox.showwarning("Uyarı", "Lütfen geçerli tarih aralığı girin.")
            return
        options['use_pub_date'] = True
        options['pub_start_date'] = start_date
        options['pub_end_date'] = end_date
    elif search_type == "cvss":
        if not cvss_severity:
            messagebox.showwarning("Uyarı", "Lütfen CVSS şiddet seviyesi seçin.")
            return
        options['use_cvss'] = True
        options['cvss_severity'] = cvss_severity
    
    # CVSS filtresi de eklenmişse
    if cvss_severity and search_type != "cvss":
        options['use_cvss'] = True
        options['cvss_severity'] = cvss_severity
    
    # Tarih filtresi de eklenmişse
    if start_date != "YYYY-MM-DD" and end_date != "YYYY-MM-DD" and search_type != "date":
        options['use_pub_date'] = True
        options['pub_start_date'] = start_date
        options['pub_end_date'] = end_date
    
    # NVD API parametrelerini oluştur
    params = build_nvd_query_params(options)
    
    # Durum çubuğunu güncelle
    status_bar.config(text="Zafiyetler aranıyor...")
    
    def search_callback(vulnerabilities):
        # Global değişkeni güncelle
        global current_vulnerabilities
        current_vulnerabilities = vulnerabilities
        
        # Sonuçları göster
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities):
                # Şiddet seviyesine göre etiket belirleme
                severity = vuln.get("severity", "Belirlenmemiş")
                severity_tag = "none"
                severity_display = "BELİRLENMEMİŞ"
                
                if severity.upper() == "CRITICAL":
                    severity_tag = "critical"
                    severity_display = "🔴 KRİTİK"
                elif severity.upper() == "HIGH":
                    severity_tag = "high"
                    severity_display = "🟠 YÜKSEK"
                elif severity.upper() == "MEDIUM":
                    severity_tag = "medium"
                    severity_display = "🟡 ORTA"
                elif severity.upper() == "LOW":
                    severity_tag = "low"
                    severity_display = "🟢 DÜŞÜK"
                
                # Zebra deseni için etiket
                row_tag = "evenrow" if i % 2 == 0 else "oddrow"
                
                # Treeview'a ekle
                vuln_treeview.insert("", tk.END, values=(
                    vuln.get("cve_id", "-"),
                    severity_display,
                    vuln.get("cvss_score", "-"),
                    vuln.get("published_date", "-"),
                    "👁️"
                ), tags=(row_tag, severity_tag))
            
            # Sayfa bilgisini güncelle
            total_results = len(vulnerabilities)
            vuln_count_label.config(text=f"Toplam: {total_results} zafiyet | Sayfa: 1/1")
            page_info_label.config(text=f"Sayfa: 1/1")
            
            # Sonuçlar varsa sayfalama butonlarını etkinleştir
            if total_results > results_per_page:
                next_page_button.config(state="normal")
            
            # Durum çubuğunu güncelle
            status_bar.config(text=f"{total_results} zafiyet bulundu.")
        else:
            # Sonuç yoksa bilgi ver
            messagebox.showinfo("Bilgi", "Arama kriterlerine uygun zafiyet bulunamadı.")
            status_bar.config(text="Zafiyet bulunamadı.")
    
    # Asenkron çalıştır
    run_async(lambda: nvd_search_cves(api_key=api_key, **params), search_callback)

# Zafiyet dışa aktarma
def export_vulnerability():
    selected_item = vuln_treeview.selection()
    if not selected_item:
        messagebox.showinfo("Bilgi", "Lütfen dışa aktarılacak bir zafiyet seçin.")
        return
    
    item = selected_item[0]
    vuln_info = vuln_treeview.item(item, "values")
    
    cve_id = vuln_info[0]
    severity = vuln_info[1]
    cvss = vuln_info[2]
    published = vuln_info[3]
    
    # Dosya adı öner
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        initialfile=f"{cve_id}_zafiyet_raporu.txt"
    )
    
    if not file_path:
        return
    
    # Açıklama ve ürün bilgilerini al
    description = vuln_desc_text.get("1.0", tk.END).strip()
    products = vuln_products_text.get("1.0", tk.END).strip()
    
    # Rapor içeriği oluştur
    report_content = f"""ZAFİYET RAPORU
==============
CVE ID: {cve_id}
Şiddet: {severity}
CVSS Skoru: {cvss}
Yayın Tarihi: {published}
Güncelleme Tarihi: {vuln_modified_value.cget("text")}

AÇIKLAMA
--------
{description}

ETKİLENEN ÜRÜNLER
----------------
{products}

RAPOR TARİHİ
-----------
{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    # Dosyaya yaz
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        messagebox.showinfo("Başarılı", f"Zafiyet raporu {file_path} konumuna kaydedildi.")
    except Exception as e:
        messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu: {str(e)}")

# Buton fonksiyonlarını ata
clear_vuln_button.config(command=clear_vuln_form)
search_vuln_button.config(command=search_vulnerabilities)
export_vuln_button.config(command=export_vulnerability)

# Sağ tık menüsü için fonksiyon
def show_context_menu(event):
    try:
        selected_item = vuln_treeview.selection()
        if selected_item:
            # Sağ tık menüsü oluştur
            context_menu = tk.Menu(vuln_treeview, tearoff=0)
            context_menu.add_command(label="Detayları Göster", command=lambda: show_vuln_details(None))
            context_menu.post(event.x_root, event.y_root)
    except:
        pass

# TreeView'a sağ tık eventi
vuln_treeview.bind("<Button-3>", show_context_menu)

#-------------------------------------------------------
# 3. SSL GÜVENLİĞİ SEKMESİ - Gelişmiş Tasarım
#-------------------------------------------------------
ssl_tab_frame = ttk.Frame(tab_ssl)
ssl_tab_frame.pack(fill="both", expand=True, padx=10, pady=10)

# SSL Arama kartı
ssl_search_card = ttk.Frame(ssl_tab_frame, style="Card.TFrame")
ssl_search_card.pack(fill="x", padx=10, pady=10)

ssl_search_frame = ttk.Frame(ssl_search_card, padding=15)
ssl_search_frame.pack(fill="x")

ttk.Label(ssl_search_frame, text="Domain:", font=('Segoe UI', 11)).grid(row=0, column=0, padx=5, pady=5)
ssl_domain_entry = ttk.Entry(ssl_search_frame, width=40, font=('Segoe UI', 11))
ssl_domain_entry.grid(row=0, column=1, padx=5, pady=5)
ssl_check_button = ttk.Button(ssl_search_frame, text="KONTROL ET", style="Action.TButton")
ssl_check_button.grid(row=0, column=2, padx=5, pady=5)

# SSL sertifika kartı - Gelişmiş görsel tasarım
ssl_card_frame = ttk.Frame(ssl_tab_frame, style="Card.TFrame")
ssl_card_frame.pack(fill="both", expand=True, padx=10, pady=10)

# SSL başlık ve durum
ssl_header_frame = ttk.Frame(ssl_card_frame)
ssl_header_frame.pack(fill="x", padx=20, pady=15)

ssl_title = ttk.Label(ssl_header_frame, text="SSL Sertifika Durumu", font=('Segoe UI', 14, 'bold'))
ssl_title.pack(side=tk.LEFT)

# Durum göstergeleri (varsayılan olarak gizli)
ssl_status_frame = ttk.Frame(ssl_card_frame)
ssl_status_frame.pack(fill="x", padx=20, pady=10)

ssl_status_icon = ttk.Label(ssl_status_frame, text="✅", font=("Segoe UI", 24), foreground=COLORS["success"])
ssl_status_icon.pack(side=tk.LEFT, padx=20)

ssl_status_label = ttk.Label(ssl_status_frame, text="Geçerli", font=("Segoe UI", 14, "bold"),
                             foreground=COLORS["success"])
ssl_status_label.pack(side=tk.LEFT)

# Sertifika içerik kartı
ssl_content_frame = ttk.Frame(ssl_card_frame, padding=15)
ssl_content_frame.pack(fill="both", expand=True, padx=20, pady=10)

# İki sütunlu düzen
ssl_content_frame.columnconfigure(0, weight=1)
ssl_content_frame.columnconfigure(1, weight=1)

# Sol kart - Geçerlilik bilgileri
validity_card = ttk.Frame(ssl_content_frame, style="Card.TFrame")
validity_card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

validity_frame = ttk.Frame(validity_card, padding=15)
validity_frame.pack(fill="both", expand=True)

# Başlık için grid kullanma
ttk.Label(validity_frame, text="Geçerlilik Bilgileri", font=("Segoe UI", 12, "bold")).grid(row=0, column=0,
                                                                                           columnspan=2, sticky="w",
                                                                                           pady=5)

# Diğer grid kullanan widget'lar aynı kalır
ttk.Label(validity_frame, text="Başlangıç:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", padx=10,
                                                                                 pady=5)
ssl_start_value = ttk.Label(validity_frame, text="-")
ssl_start_value.grid(row=1, column=1, sticky="w", pady=5)

ttk.Label(validity_frame, text="Bitiş:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", padx=10,
                                                                             pady=5)
ssl_end_value = ttk.Label(validity_frame, text="-")
ssl_end_value.grid(row=2, column=1, sticky="w", pady=5)

ttk.Label(validity_frame, text="Kalan Süre:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w", padx=10,
                                                                                  pady=5)
ssl_remaining_value = ttk.Label(validity_frame, text="-")
ssl_remaining_value.grid(row=3, column=1, sticky="w", pady=5)

# İlerleme çubuğu
ssl_progress_frame = ttk.Frame(validity_frame)
ssl_progress_frame.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=15)

ssl_progressbar = ttk.Progressbar(ssl_progress_frame, length=250)
ssl_progressbar.pack(fill="x")

# Sağ kart - Sertifika detayları
cert_card = ttk.Frame(ssl_content_frame, style="Card.TFrame")
cert_card.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

# Sertifika detayları kısmı için grid yaklaşımı
cert_details_frame = ttk.Frame(cert_card, padding=15)
cert_details_frame.pack(fill="both", expand=True)

# Hepsini grid() ile düzenle
ttk.Label(cert_details_frame, text="Sertifika Detayları",
          font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=5)

ttk.Label(cert_details_frame, text="Yayınlayan:",
          font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", padx=10, pady=5)
ssl_issuer_value = ttk.Label(cert_details_frame, text="-")
ssl_issuer_value.grid(row=1, column=1, sticky="w", pady=5)

ttk.Label(cert_details_frame, text="Algoritma:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w",
                                                                                     padx=10, pady=5)
ssl_algo_value = ttk.Label(cert_details_frame, text="-")
ssl_algo_value.grid(row=2, column=1, sticky="w", pady=5)

ttk.Label(cert_details_frame, text="Konu:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w", padx=10,
                                                                                pady=5)
ssl_subject_value = ttk.Label(cert_details_frame, text="-")
ssl_subject_value.grid(row=3, column=1, sticky="w", pady=5)

# Alt kart - Ek Bilgiler
extra_card = ttk.Frame(ssl_content_frame, style="Card.TFrame")
extra_card.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

extra_frame = ttk.Frame(extra_card, padding=10)
extra_frame.pack(fill="x")

ttk.Label(extra_frame, text="Güvenlik Önerileri", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=5)
ssl_recommendations = ttk.Label(extra_frame, text="Domain için SSL kontrolü yapılmadı.", wraplength=800)
ssl_recommendations.pack(anchor="w", padx=10, pady=5)


# SSL kontrolü için gerekli arayüz güncellemeleri
def ssl_kontrol_et():
    domain = ssl_domain_entry.get()
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin.")
        return

    # Butonu geçici olarak devre dışı bırak ve metni değiştir
    ssl_check_button.config(text="KONTROL EDİLİYOR...", state="disabled")
    # Önceki sonuçları temizle (isteğe bağlı)
    ssl_status_icon.config(text="⏳", foreground="gray")
    ssl_status_label.config(text="Kontrol ediliyor...", foreground="gray")
    ssl_start_value.config(text="-")
    ssl_end_value.config(text="-")
    ssl_remaining_value.config(text="-")
    ssl_progressbar["value"] = 0
    ssl_issuer_value.config(text="-")
    ssl_subject_value.config(text="-")
    ssl_algo_value.config(text="-")
    ssl_recommendations.config(text="Lütfen bekleyin, SSL bilgileri alınıyor...")

    def ssl_callback(cert_info):
        # Butonu tekrar aktif et ve metni eski haline getir
        ssl_check_button.config(text="KONTROL ET", state="normal")

        if cert_info is None:  # crtsh_ssl_bilgisi None dönerse (beklenmedik bir durum)
            cert_info = {"error": "Bilinmeyen bir hata oluştu. Fonksiyon None değeri döndürdü."}

        if "error" not in cert_info or not cert_info.get("error"):  # Hata yoksa veya error boşsa
            is_self_signed = cert_info.get("self_signed", False)  # crt.sh için bu hep False olacak

            # Tarihleri formatla (datetime nesneleri geldiyse)
            not_before_dt = cert_info.get("not_before")
            not_after_dt = cert_info.get("not_after")

            start_date_str = not_before_dt.strftime('%Y-%m-%d %H:%M:%S UTC') if not_before_dt else "Bilinmiyor"
            end_date_str = not_after_dt.strftime('%Y-%m-%d %H:%M:%S UTC') if not_after_dt else "Bilinmiyor"

            kalan_gun = cert_info.get("kalan_gun", 0)

            ssl_start_value.config(text=start_date_str)
            ssl_end_value.config(text=end_date_str)

            if not_after_dt:  # Bitiş tarihi varsa kalan günü göster
                ssl_remaining_value.config(text=f"{kalan_gun} gün")
            else:  # Bitiş tarihi yoksa (örn. bazı kök sertifikalar)
                ssl_remaining_value.config(text="Belirsiz")

            # Durum bilgisi güncelle
            # is_self_signed crt.sh için her zaman false olacağından o bloklar çalışmayacak.
            # Sadece kalan gün bazlı durumları ele alıyoruz.
            if not not_after_dt:  # Bitiş tarihi olmayan sertifikalar (örn. kök CA'lar)
                ssl_status_icon.config(text="ℹ️", foreground=COLORS.get("info", "blue"))  # Renklerinizde info varsa
                ssl_status_label.config(text="Sertifika (Bitiş Tarihi Yok)", foreground=COLORS.get("info", "blue"))
                ssl_progressbar.config(style="")  # Normal stil
                ssl_progressbar["value"] = 100  # Sonsuz geçerli gibi
                ssl_recommendations.config(
                    text=f"Bu sertifikanın belirli bir bitiş tarihi yok (genellikle kök sertifikalar). TLS Versiyonu: {cert_info.get('tls_version', 'Bilinmiyor')}.")
            elif kalan_gun > 30:
                ssl_status_icon.config(text="✅", foreground=COLORS["success"])
                ssl_status_label.config(text="Sertifika Geçerli", foreground=COLORS["success"])
                ssl_progressbar.config(style="")  # Varsayılan stil (Success.Horizontal.TProgressbar tanımlıysa o)
            elif kalan_gun > 0:
                ssl_status_icon.config(text="⚠️", foreground=COLORS["warning"])
                ssl_status_label.config(text=f"Sertifika {kalan_gun} gün içinde sona erecek",
                                        foreground=COLORS["warning"])
                ssl_progressbar.config(style="Warning.Horizontal.TProgressbar")
            else:  # kalan_gun <= 0
                ssl_status_icon.config(text="❌", foreground=COLORS["danger"])
                ssl_status_label.config(text="Sertifika Süresi Dolmuş", foreground=COLORS["danger"])
                ssl_progressbar.config(style="Danger.Horizontal.TProgressbar")

            # İlerleme çubuğunu güncelle
            if not_after_dt:  # Sadece bitiş tarihi varsa ilerleme çubuğu mantıklı
                total_duration = cert_info.get("total_duration_days", 0)
                if total_duration > 0 and kalan_gun >= 0:  # Süresi dolmamış ve toplam süre biliniyorsa
                    progress_value = min(100, max(0, int((kalan_gun / total_duration) * 100)))
                elif kalan_gun > 0:  # Toplam süre bilinmiyor ama hala geçerli
                    # Geçerli sertifikalar için genellikle 90 (Let's Encrypt) veya 365+ gün olur
                    # Bu durumda kalan gün / (kalan_gün + (not_after - not_before).days) gibi bir oran da düşünülebilir
                    # Şimdilik basit bir gösterim:
                    progress_value = 50  # Orta bir değer
                    if kalan_gun > 60: progress_value = 75
                    if kalan_gun < 15: progress_value = 25
                elif kalan_gun <= 0:  # Süresi dolmuş
                    progress_value = 0
                else:  # Diğer durumlar
                    progress_value = 0
                ssl_progressbar["value"] = progress_value
            elif not not_after_dt:  # Bitiş tarihi yoksa (örn. kök CA)
                ssl_progressbar["value"] = 100  # Tam dolu göster

            # Sertifika detaylarını güncelle
            # issuer_details = {"organizationName": "...", "commonName": "...", "fullName": "..."}
            issuer_display_name = cert_info.get("issuer", {}).get("organizationName", "Bilinmiyor")
            if issuer_display_name == "Bilinmiyor":  # Eğer O= yoksa CN= dene (parse_issuer_details bunu yapıyor)
                issuer_display_name = cert_info.get("issuer", {}).get("commonName", "Bilinmiyor")
            ssl_issuer_value.config(text=issuer_display_name)

            # Konu (Subject) için Common Name
            subject_cn = cert_info.get("subject", {}).get("commonName", domain)
            ssl_subject_value.config(text=subject_cn if subject_cn else domain)  # Eğer CN boşsa domaini göster

            # İmza Algoritması -- Artık crt.sh modülü gerçek imza algoritmasını getiriyor
            ssl_algo_value.config(text=cert_info.get("signature_algorithm", "-"))

            # Güvenlik önerileri (is_self_signed kısmı crt.sh için çalışmayacak)
            if not not_after_dt:
                # Zaten yukarıda ayarlandı.
                pass
            elif kalan_gun > 30:
                ssl_recommendations.config(
                    text=f"Sertifika durumu iyi. TLS Versiyonu: {cert_info.get('tls_version', 'Bilinmiyor')}. İmza Algoritması: {cert_info.get('signature_algorithm', 'Bilinmiyor')}. Periyodik kontrollere devam edin.")
            elif kalan_gun > 0:
                ssl_recommendations.config(
                    text=f"Sertifikanız yakında sona erecek! TLS Versiyonu: {cert_info.get('tls_version', 'Bilinmiyor')}. İmza Algoritması: {cert_info.get('signature_algorithm', 'Bilinmiyor')}. En kısa sürede yenilemeniz önerilir.")
            else:
                ssl_recommendations.config(
                    text=f"Sertifikanızın süresi dolmuş! TLS Versiyonu: {cert_info.get('tls_version', 'Bilinmiyor')}. İmza Algoritması: {cert_info.get('signature_algorithm', 'Bilinmiyor')}. Bu durum kullanıcılarda güvenlik uyarılarına neden olur ve sitenize erişimi zorlaştırır. HEMEN yenileyin!")

        else:  # Hata varsa
            error_message = cert_info.get('error', 'Bilinmeyen bir SSL hatası oluştu.')
            ssl_status_icon.config(text="❌", foreground=COLORS["danger"])
            ssl_status_label.config(text="Sertifika Hatası", foreground=COLORS["danger"])
            ssl_start_value.config(text="-")
            ssl_end_value.config(text="-")
            ssl_remaining_value.config(text="-")
            ssl_progressbar["value"] = 0
            ssl_progressbar.config(style="Danger.Horizontal.TProgressbar")
            ssl_issuer_value.config(text="-")
            ssl_subject_value.config(text="-")
            ssl_algo_value.config(text="-")
            ssl_recommendations.config(text=f"SSL sertifikası alınamadı: {error_message}")

    # Asenkron çalıştırılacak fonksiyonu crtsh_ssl_bilgisi olarak değiştirin
    # run_async sizin tanımladığınız bir yardımcı fonksiyon olmalı (örn: threading ile)
    # Eğer run_async yoksa, doğrudan çağırıp GUI'nin donmasını engellemek için threading kullanın:
    # import threading
    # threading.Thread(target=lambda: ssl_callback(crtsh_ssl_bilgisi(domain)), daemon=True).start()
    # Eğer run_async threading'i zaten hallediyorsa:
    run_async(lambda: crtsh_ssl_bilgisi(domain), ssl_callback)


# SSL Kontrol butonuna komut ekle
ssl_check_button.config(command=ssl_kontrol_et)
# SSL ilerleme çubuğu stilleri
style.configure("Horizontal.TProgressbar", background=COLORS["success"])
style.configure("Warning.Horizontal.TProgressbar", background=COLORS["warning"])
style.configure("Danger.Horizontal.TProgressbar", background=COLORS["danger"])

#-------------------------------------------------------
# 4. GOOGLE DORKS SEKMESİ
#-------------------------------------------------------
dorks_main_frame = ttk.Frame(tab_dorks)
dorks_main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Üst arama bölümü
dork_search_frame = ttk.Frame(dorks_main_frame)
dork_search_frame.pack(fill="x", padx=10, pady=10)

ttk.Label(dork_search_frame, text="Domain:").grid(row=0, column=0, padx=5, pady=5)
dork_domain_entry = ttk.Entry(dork_search_frame, width=40)
dork_domain_entry.grid(row=0, column=1, padx=5, pady=5)

# Sonuç sayısı seçici
ttk.Label(dork_search_frame, text="Sonuç Sayısı:").grid(row=0, column=2, padx=(10, 0), pady=5)
results_spinbox = ttk.Spinbox(dork_search_frame, from_=1, to=20, width=5)
results_spinbox.grid(row=0, column=3, padx=(0, 10), pady=5)
results_spinbox.set(5)  # Varsayılan değer

# Önce buton tanımı yapılır, ama komut eklemeden
search_dork_button = ttk.Button(dork_search_frame, text="ARAMA", style="Action.TButton")
search_dork_button.grid(row=0, column=4, padx=5, pady=5)

# 582. satırdan önce bu fonksiyonu ekleyin
def clear_dork_results():
    dork_results_text.delete(1.0, tk.END)
    status_bar.config(text="Sonuçlar temizlendi")

def export_dork_results():
    content = dork_results_text.get(1.0, tk.END)
    if not content.strip():
        messagebox.showinfo("Bilgi", "Dışa aktarılacak sonuç bulunamadı.")
        return
        
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Sonuçları Dışa Aktar"
    )
        
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        messagebox.showinfo("Başarılı", f"Sonuçlar {file_path} konumuna kaydedildi.")

# DAHA SONRA butonları tanımlayın
clear_button = ttk.Button(dork_search_frame, text="Temizle", command=clear_dork_results)
export_button = ttk.Button(dork_search_frame, text="Dışa Aktar", command=export_dork_results)

# Ana içerik - iki sütunlu frame
dork_content_frame = ttk.Frame(dorks_main_frame)
dork_content_frame.pack(fill="both", expand=True, padx=10, pady=10)
dork_content_frame.columnconfigure(0, weight=1)
dork_content_frame.columnconfigure(1, weight=3)

# Sol taraf - Hazır dorklar
dork_presets_frame = ttk.LabelFrame(dork_content_frame, text="Hazır Dorklar")
dork_presets_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

# Checkbox değişkenleri
pdf_var = tk.BooleanVar()
dir_var = tk.BooleanVar()
login_var = tk.BooleanVar()
sql_var = tk.BooleanVar()
subdomain_var = tk.BooleanVar()
pass_var = tk.BooleanVar()

ttk.Checkbutton(dork_presets_frame, text="PDF dosyalar", variable=pdf_var).pack(anchor="w", padx=10, pady=5)
ttk.Checkbutton(dork_presets_frame, text="Açık dizinler", variable=dir_var).pack(anchor="w", padx=10, pady=5)
ttk.Checkbutton(dork_presets_frame, text="Login sayfaları", variable=login_var).pack(anchor="w", padx=10, pady=5)
ttk.Checkbutton(dork_presets_frame, text="Şifre içeren sayfalar", variable=pass_var).pack(anchor="w", padx=10, pady=5)
ttk.Checkbutton(dork_presets_frame, text="SQL dosyaları", variable=sql_var).pack(anchor="w", padx=10, pady=5)
ttk.Checkbutton(dork_presets_frame, text="Alt domainler", variable=subdomain_var).pack(anchor="w", padx=10, pady=5)

# Sağ taraf - Sonuçlar
dork_results_frame = ttk.LabelFrame(dork_content_frame, text="Sonuçlar")
dork_results_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

dork_results_text = tk.Text(dork_results_frame, wrap=tk.WORD, height=15)
dork_results_text.pack(fill="both", expand=True, padx=5, pady=5)

# Text widget'ı için tag tanımlaması (başlıklar için)
dork_results_text.tag_configure("header", font=("Segoe UI", 11, "bold"), foreground=COLORS["primary"])

# Alt kısım - Özel dork oluşturucu
dork_custom_frame = ttk.LabelFrame(dorks_main_frame, text="Özel Dork Oluşturucu")
dork_custom_frame.pack(fill="x", padx=10, pady=10)

ttk.Label(dork_custom_frame, text="site:[domain]").grid(row=0, column=0, padx=5, pady=10)
dork_custom_entry = ttk.Entry(dork_custom_frame, width=40)
dork_custom_entry.grid(row=0, column=1, padx=5, pady=10)

# ÖNEMLİ: Önce fonksiyonu tanımlayın
def add_custom_dork():
    domain = dork_domain_entry.get()
    ozel_dork = dork_custom_entry.get()
    
    # Sonuç sayısını al
    try:
        num_results = int(results_spinbox.get())
        if num_results < 1:
            messagebox.showwarning("Uyarı", "Sonuç sayısı en az 1 olmalıdır.")
            return
    except ValueError:
        messagebox.showwarning("Uyarı", "Geçerli bir sonuç sayısı giriniz.")
        return
    
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin.")
        return
        
    if not ozel_dork:
        messagebox.showwarning("Uyarı", "Lütfen özel dork girin.")
        return
    
    def custom_dork_callback(sonuclar):
        # Text widget'ına önceki sonuçları silmeden ekle
        dork_results_text.insert(tk.END, f"\n--- ÖZEL DORK: {ozel_dork} ---\n\n", "header")
        
        if not sonuclar:
            dork_results_text.insert(tk.END, "Sonuç bulunamadı.\n\n")
        else:
            for url in sonuclar:
                dork_results_text.insert(tk.END, f"• {url}\n")
            dork_results_text.insert(tk.END, "\n")
        
        # Status bar'ı güncelle
        status_bar.config(text=f"Özel dork taraması tamamlandı: {domain}")
        
        # Ekle butonunu normal durumuna getir
        add_dork_button.config(state="normal", text="Ekle")
    
    # Durum çubuğunu güncelle
    status_bar.config(text=f"Özel dork taraması çalışıyor: {domain}...")
    
    # Ekle butonunu devre dışı bırak
    add_dork_button.config(state="disabled", text="Aranıyor...")
    
    # Asenkron çalıştır
    run_async(lambda: ozel_dork_ara(domain, ozel_dork, num_results), custom_dork_callback)

# SONRA butonu tanımlayın
add_dork_button = ttk.Button(dork_custom_frame, text="Ekle", command=add_custom_dork)
add_dork_button.grid(row=0, column=2, padx=5, pady=10)

# Sonra fonksiyon tanımlanır
def dork_search():
    domain = dork_domain_entry.get()
    if not domain:
        messagebox.showwarning("Uyarı", "Lütfen bir domain girin.")
        return
    
    # Sonuç sayısını al
    try:
        num_results = int(results_spinbox.get())
        if num_results < 1:
            messagebox.showwarning("Uyarı", "Sonuç sayısı en az 1 olmalıdır.")
            return
    except ValueError:
        messagebox.showwarning("Uyarı", "Geçerli bir sonuç sayısı giriniz.")
        return
    
    # Seçili dorkları belirle
    secilen_dorklar = []
    if pdf_var.get():
        secilen_dorklar.append("pdf_dosyalari")
    if dir_var.get():
        secilen_dorklar.append("acik_dizinler")
    if login_var.get():
        secilen_dorklar.append("login_sayfalari")
    if pass_var.get():
        secilen_dorklar.append("sifre_sayfalar")
    if sql_var.get():
        secilen_dorklar.append("sql_dosyalari")
    if subdomain_var.get():
        secilen_dorklar.append("alt_domainler")
    
    # Hiçbir dork seçilmediyse uyarı ver
    if not secilen_dorklar:
        messagebox.showinfo("Bilgi", "Lütfen en az bir dork tipi seçin.")
        return
    
    def dork_callback(sonuclar):
        # Text widget'ını temizle
        dork_results_text.delete(1.0, tk.END)
        
        # Sonuçları ekle
        for kategori, urls in sonuclar.items():
            dork_results_text.insert(tk.END, f"\n--- {kategori} ---\n\n", "header")
            
            if not urls:
                dork_results_text.insert(tk.END, "Sonuç bulunamadı.\n\n")
            else:
                for url in urls:
                    dork_results_text.insert(tk.END, f"• {url}\n")
                dork_results_text.insert(tk.END, "\n")
        
        # Status bar'ı güncelle
        status_bar.config(text=f"Google Dorks taraması tamamlandı: {domain}")
        
        # Arama butonunu normal durumuna getir
        search_dork_button.config(state="normal", text="ARAMA")
    
    # Durum çubuğunu güncelle
    status_bar.config(text=f"Google Dorks taraması çalışıyor: {domain}...")
    
    # Arama butonunu devre dışı bırak ve durumunu göster
    search_dork_button.config(state="disabled", text="Aranıyor...")
    
    # Asenkron çalıştır
    run_async(lambda: dork_ara(domain, secilen_dorklar, num_results), dork_callback)

# En son buton'a komut atanır
search_dork_button.config(command=dork_search)

#-------------------------------------------------------
# 5. VERİ İHLALİ SEKMESİ - KVKK Veri İhlali Arama
#-------------------------------------------------------
try:
    from KvkkVeriIhlali.vericrawler.Veritemizleme import veri_temizle_ve_analiz_et, temizle_metin, cikart_tarih, cikart_kisi_sayisi, cikart_veri_turleri, cikart_iletisim_bilgileri
except:
    # Eğer modül yüklenemezse basit fonksiyonlar tanımla
    def veri_temizle_ve_analiz_et():
        try:
            import json
            with open("KvkkVeriIhlali/vericrawler/bilgi.json", "r", encoding="utf-8") as f:
                veri = json.load(f)
            return [{"baslik": item["AramaSonucuBaslik"], "icerik": " ".join(item["AramaSonucYazi"])} for item in veri]
        except:
            return []
    
    def temizle_metin(metin): return metin
    def cikart_tarih(metin): return []
    def cikart_kisi_sayisi(metin): return None
    def cikart_veri_turleri(metin): return []
    def cikart_iletisim_bilgileri(metin): return {"telefonlar": [], "adresler": []}

breach_main_frame = ttk.Frame(tab_breach)
breach_main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Arama Bölümü
breach_search_card = ttk.Frame(breach_main_frame, style="Card.TFrame")
breach_search_card.pack(fill="x", padx=10, pady=10)

breach_search_frame = ttk.Frame(breach_search_card, padding=15)
breach_search_frame.pack(fill="x")

ttk.Label(breach_search_frame, text="Aramak istediğiniz veri ihlali konusu:", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w", padx=5, pady=5)
breach_search_entry = ttk.Entry(breach_search_frame, width=40, font=('Segoe UI', 11))
breach_search_entry.grid(row=0, column=1, padx=5, pady=5)

breach_search_button = ttk.Button(breach_search_frame, text="ARA", style="Action.TButton")
breach_search_button.grid(row=0, column=2, padx=5, pady=5)

# Örnek arama önerileri
ttk.Label(breach_search_frame, text="Örnek: \"banka\", \"sağlık\", \"turknet\"", font=("Segoe UI", 9, "italic")).grid(row=1, column=1, sticky="w", padx=5)

# Veri İhlali Bildirimleri Bölümü
breach_list_frame = ttk.LabelFrame(breach_main_frame, text="Veri İhlali Bildirimleri")
breach_list_frame.pack(fill="x", padx=10, pady=10)

# TreeView yerine Listbox kullanıyoruz (çünkü seçim daha kolay)
breach_results_count = ttk.Label(breach_list_frame, text="Arama Sonuçları (0 sonuç):", anchor="w")
breach_results_count.pack(fill="x", padx=10, pady=(10, 5))

breach_listbox_frame = ttk.Frame(breach_list_frame)
breach_listbox_frame.pack(fill="both", expand=True, padx=10, pady=5)

breach_y_scrollbar = ttk.Scrollbar(breach_listbox_frame, orient="vertical")
breach_y_scrollbar.pack(side="right", fill="y")

# Listbox sonuçları göstermek için
breach_listbox = tk.Listbox(
    breach_listbox_frame, 
    height=5,
    font=("Segoe UI", 10),
    selectmode=tk.SINGLE,
    yscrollcommand=breach_y_scrollbar.set
)
breach_listbox.pack(fill="both", expand=True)
breach_y_scrollbar.config(command=breach_listbox.yview)

# Bildirim İçeriği Bölümü
breach_content_frame = ttk.LabelFrame(breach_main_frame, text="Bildirim İçeriği")
breach_content_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Başlık
breach_title_var = tk.StringVar()
breach_title_label = ttk.Label(breach_content_frame, textvariable=breach_title_var, font=("Segoe UI", 11, "bold"), wraplength=800)
breach_title_label.pack(fill="x", padx=10, pady=(10, 5))

# İçerik
breach_content_text = tk.Text(breach_content_frame, wrap="word", height=15, font=("Segoe UI", 10))
breach_content_text.pack(fill="both", expand=True, padx=10, pady=5)

# Metin özellikleri
breach_content_text.tag_configure("bold", font=("Segoe UI", 10, "bold"))
breach_content_text.tag_configure("italic", font=("Segoe UI", 10, "italic"))
breach_content_text.tag_configure("header", font=("Segoe UI", 11, "bold"), foreground=COLORS["primary"])
breach_content_text.tag_configure("subheader", font=("Segoe UI", 10, "bold"), foreground=COLORS["secondary"])

# Butonlar
breach_button_frame = ttk.Frame(breach_content_frame)
breach_button_frame.pack(fill="x", padx=10, pady=(5, 10))

show_full_button = ttk.Button(breach_button_frame, text="TÜM İÇERİĞİ GÖSTER", width=20)
show_full_button.pack(side=tk.LEFT, padx=5)

copy_button = ttk.Button(breach_button_frame, text="KOPYALA", width=15)
copy_button.pack(side=tk.LEFT, padx=5)

# İçerik düzenleme seçenekleri
format_frame = ttk.LabelFrame(breach_main_frame, text="İçerik Düzenleme")
format_frame.pack(fill="x", padx=10, pady=10)

format_options_frame = ttk.Frame(format_frame, padding=10)
format_options_frame.pack(fill="x")

# Seçenekler
clean_spaces_var = tk.BooleanVar(value=True)
ttk.Checkbutton(format_options_frame, text="Gereksiz boşlukları temizle", 
                variable=clean_spaces_var).grid(row=0, column=0, padx=20, pady=5, sticky="w")

remove_html_var = tk.BooleanVar(value=True)
ttk.Checkbutton(format_options_frame, text="HTML etiketlerini kaldır", 
                variable=remove_html_var).grid(row=0, column=1, padx=20, pady=5, sticky="w")

highlight_var = tk.BooleanVar(value=True)
ttk.Checkbutton(format_options_frame, text="Önemli bilgileri vurgula", 
                variable=highlight_var).grid(row=1, column=0, padx=20, pady=5, sticky="w")

merge_para_var = tk.BooleanVar(value=False)
ttk.Checkbutton(format_options_frame, text="Paragrafları birleştir", 
                variable=merge_para_var).grid(row=1, column=1, padx=20, pady=5, sticky="w")

# Tüm veri ihlali bildirimlerini yükle
def load_breach_data():
    try:
        # Veritemizleme.py'deki fonksiyonu çağır
        return veri_temizle_ve_analiz_et()
    except Exception as e:
        messagebox.showerror("Hata", f"Veri ihlali bildirimleri yüklenemedi: {str(e)}")
        return []

# Global değişken
breach_data = []

# Arama fonksiyonu
def search_breach_data():
    global breach_data
    
    # Eğer veri henüz yüklenmemişse yükle
    if not breach_data:
        breach_data = veri_temizle_ve_analiz_et()
    
    # Arama sorgusunu al
    query = breach_search_entry.get().lower()
    
    # Listbox'ı temizle
    breach_listbox.delete(0, tk.END)
    
    # Eğer arama sorgusu boşsa tüm verileri göster
    if not query:
        results = breach_data
    else:
        # Arama sorgusu varsa filtrele
        results = []
        for item in breach_data:
            if (query in item["baslik"].lower() or 
                query in item["icerik"].lower()):
                results.append(item)
    
    # Sonuçları listbox'a ekle
    for i, item in enumerate(results):
        # Veri ihlali mi kontrol et
        if item.get("veri_ihlali_mi", False):
            baslik = "🔴 " + item["baslik"]  # Veri ihlali bildirimlerini kırmızı işaretle
        else:
            baslik = item["baslik"]
            
        breach_listbox.insert(tk.END, baslik)
        # Alternatif sıralı görünüm için tag kullan
        breach_listbox.itemconfig(i, background="#f9f9f9" if i % 2 == 0 else "white")
    
    # Sonuç sayısını güncelle
    breach_results_count.config(text=f"Arama Sonuçları ({len(results)} sonuç):")
    
    # İlk sonucu otomatik seçme
    if results:
        breach_listbox.selection_set(0)
        show_breach_content(results[0])

# İçerik gösterme fonksiyonu güncellendi
def show_breach_content(item):
    # Başlığı güncelle
    breach_title_var.set(item["baslik"])
    
    # İçerik metni
    breach_content_text.config(state="normal")
    breach_content_text.delete("1.0", tk.END)
    
    # Eğer formatlanmış içerik varsa ve vurgulama seçeneği işaretliyse
    if "formatli_icerik" in item and highlight_var.get():
        # Formatlanmış metni parçalara ayır
        sections = item["formatli_icerik"].split("\n")
        
        # Metin parçalarını formatlayarak ekle
        for section in sections:
            if section.startswith("Başlık:"):
                breach_content_text.insert(tk.END, section + "\n", "header")
            elif section.startswith("ÖZET BİLGİLER:") or section.startswith("DETAYLAR:"):
                breach_content_text.insert(tk.END, "\n" + section + "\n", "subheader")
            elif section.startswith("•"):
                breach_content_text.insert(tk.END, section + "\n", "bold")
            else:
                breach_content_text.insert(tk.END, section + "\n")
    else:
        # Ham içeriği göster
        ham_icerik = item["icerik"]
        
        # Eğer veri ihlali mi bilgisi varsa
        if item.get("veri_ihlali_mi", False):
            # Gereksiz boşlukları temizle
            if clean_spaces_var.get():
                ham_icerik = re.sub(r'\s+', ' ', ham_icerik)
            
            # Paragraf birleştirme aktifse
            if merge_para_var.get():
                ham_icerik = ham_icerik.replace("\n", " ")
            
            # Tarih, kişi sayısı gibi bilgileri vurgula
            tarihler = item.get("tarihler", [])
            kisi_sayisi = item.get("kisi_sayisi", None)
            veri_turleri = item.get("veri_turleri", [])
            
            # Özet bilgileri ekle
            ozet = ""
            if tarihler or kisi_sayisi or veri_turleri:
                ozet += "--- ÖNEMLİ BİLGİLER ---\n"
                if tarihler:
                    ozet += f"• Tarih: {', '.join(tarihler)}\n"
                if kisi_sayisi:
                    ozet += f"• Etkilenen Kişi Sayısı: {kisi_sayisi}\n"
                if veri_turleri:
                    ozet += f"• Sızan Veri Türleri: {', '.join(veri_turleri)}\n"
                ozet += "\n--- İÇERİK ---\n\n"
                
                breach_content_text.insert(tk.END, ozet, "bold")
        
        breach_content_text.insert(tk.END, ham_icerik)
    
    breach_content_text.config(state="disabled")

# Listbox seçim olayı güncellenmiş hali
def on_breach_select(event):
    global breach_data
    
    selection = breach_listbox.curselection()
    if selection:
        index = selection[0]
        selected_title = breach_listbox.get(index)
        
        # Başında işaret varsa kaldır
        if selected_title.startswith("🔴 "):
            selected_title = selected_title[2:]
        
        # Seçilen başlığı bul
        for item in breach_data:
            if item["baslik"] == selected_title:
                show_breach_content(item)
                break

# Tüm içeriği göster butonu
def show_full_content():
    selection = breach_listbox.curselection()
    if selection:
        index = selection[0]
        selected_title = breach_listbox.get(index)
        
        # Seçilen başlığı bul
        for item in breach_data:
            if item["baslik"] == selected_title:
                # Yeni pencere oluştur
                full_window = tk.Toplevel(pencere)
                full_window.title(item["baslik"])
                full_window.geometry("800x600")
                
                # Tam içerik için text widget
                full_text = tk.Text(full_window, wrap="word", font=("Segoe UI", 11))
                full_text.pack(fill="both", expand=True, padx=20, pady=20)
                
                # İçeriği ekle
                full_text.insert("1.0", item["icerik"])
                full_text.config(state="disabled")
                
                # Kaydırma çubuğu
                full_scroll = ttk.Scrollbar(full_text, command=full_text.yview)
                full_scroll.pack(side="right", fill="y")
                full_text.config(yscrollcommand=full_scroll.set)
                
                break

# İçeriği kopyala butonu
def copy_content():
    selection = breach_listbox.curselection()
    if selection:
        index = selection[0]
        selected_title = breach_listbox.get(index)
        
        # Başında işaret varsa kaldır
        if selected_title.startswith("🔴 "):
            selected_title = selected_title[2:]
        
        for item in breach_data:
            if item["baslik"] == selected_title:
                # Eğer formatlanmış içerik varsa onu kopyala, yoksa ham içeriği
                if "formatli_icerik" in item and highlight_var.get():
                    content_to_copy = item["formatli_icerik"]
                else:
                    content_to_copy = item["icerik"]
                
                # İçeriği panoya kopyala
                pencere.clipboard_clear()
                pencere.clipboard_append(content_to_copy)
                
                # Kullanıcıya bilgi ver
                status_bar.config(text="İçerik panoya kopyalandı!")
                
                # 3 saniye sonra durum çubuğunu sıfırla
                pencere.after(3000, lambda: status_bar.config(text="Hazır"))
                
                break

# Butonlara işlevleri bağla
breach_search_button.config(command=search_breach_data)
breach_listbox.bind('<<ListboxSelect>>', on_breach_select)
show_full_button.config(command=show_full_content)
copy_button.config(command=copy_content)

# Uygulama açıldığında veri ihlali bildirimlerini yükle
breach_data = load_breach_data()

# Uygulama açıldığında varsayılan olarak tüm bildirimleri göster
search_breach_data()

#-------------------------------------------------------
# 6. NETWORK TARAMA SEKMESİ
#-------------------------------------------------------
network_main_frame = ttk.Frame(tab_network)
network_main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Üst arama bölümü
network_search_frame = ttk.Frame(network_main_frame, style="Card.TFrame")
network_search_frame.pack(fill="x", padx=10, pady=10)

network_input_frame = ttk.Frame(network_search_frame, padding=15)
network_input_frame.pack(fill="x")

ttk.Label(network_input_frame, text="Domain/IP:").grid(row=0, column=0, padx=5, pady=5)
network_target_entry = ttk.Entry(network_input_frame, width=40)
network_target_entry.grid(row=0, column=1, padx=5, pady=5)

# Tarama seçenekleri
network_option_frame = ttk.LabelFrame(network_main_frame, text="Tarama Seçenekleri")
network_option_frame.pack(fill="x", padx=10, pady=10)

# Tarama türleri için frame
scan_types_frame = ttk.Frame(network_option_frame)
scan_types_frame.pack(fill="x", padx=10, pady=5)

# Tarama türü seçenekleri
quick_scan_var = tk.BooleanVar(value=True)
syn_scan_var = tk.BooleanVar()
service_detect_var = tk.BooleanVar(value=True)

ttk.Label(scan_types_frame, text="Tarama Türü:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
ttk.Checkbutton(scan_types_frame, text="Hızlı Tarama", variable=quick_scan_var).grid(row=0, column=1, padx=20, pady=5, sticky="w")
ttk.Checkbutton(scan_types_frame, text="SYN Tarama", variable=syn_scan_var).grid(row=1, column=1, padx=20, pady=5, sticky="w")
ttk.Checkbutton(scan_types_frame, text="Servis Tespiti", variable=service_detect_var).grid(row=2, column=1, padx=20, pady=5, sticky="w")

# Portlar için frame
ports_frame = ttk.Frame(network_option_frame)
ports_frame.pack(fill="x", padx=10, pady=5)

ttk.Label(ports_frame, text="Portlar:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
default_ports = "21,22,25,80,443,3306,8080"
ports_entry = ttk.Entry(ports_frame, width=40)
ports_entry.grid(row=0, column=1, padx=5, pady=5)
ports_entry.insert(0, default_ports)

# Tarama butonu
network_button_frame = ttk.Frame(network_option_frame)
network_button_frame.pack(fill="x", padx=10, pady=10)

scan_button = ttk.Button(network_button_frame, text="TARAMA BAŞLAT", style="Action.TButton")
scan_button.pack(side=tk.LEFT, padx=5)

export_network_button = ttk.Button(network_button_frame, text="Dışa Aktar", command=lambda: export_network_results())
export_network_button.pack(side=tk.LEFT, padx=5)

# Sonuç paneli
network_results_frame = ttk.LabelFrame(network_main_frame, text="Sonuçlar")
network_results_frame.pack(fill="both", expand=True, padx=10, pady=10)

# OS Bilgisi kartı
os_info_frame = ttk.LabelFrame(network_results_frame, text="İşletim Sistemi Bilgileri")
os_info_frame.pack(fill="x", padx=10, pady=10)

# Label yerine bir TreeView kullanın:
os_info_treeview = ttk.Treeview(
    os_info_frame, 
    columns=("Kaynak", "İşletim Sistemi", "Güven"), 
    show="headings",
    height=4
)

os_info_treeview.column("Kaynak", width=120, minwidth=120)
os_info_treeview.column("İşletim Sistemi", width=300, minwidth=200)
os_info_treeview.column("Güven", width=100, minwidth=100)

os_info_treeview.heading("Kaynak", text="Tespit Kaynağı")
os_info_treeview.heading("İşletim Sistemi", text="İşletim Sistemi")
os_info_treeview.heading("Güven", text="Güven Seviyesi")

os_info_treeview.pack(fill="x", expand=True, padx=5, pady=5)

# Zebra çizgileri için tag'ler
os_info_treeview.tag_configure('oddrow', background='#f9f9f9')
os_info_treeview.tag_configure('evenrow', background='white')
os_info_treeview.tag_configure('high', foreground=COLORS["success"])
os_info_treeview.tag_configure('medium', foreground=COLORS["warning"])
os_info_treeview.tag_configure('low', foreground=COLORS["danger"])

# Port bilgileri için TreeView
ports_result_frame = ttk.LabelFrame(network_results_frame, text="Port Bilgileri")
ports_result_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Scrollbar'lar
ports_y_scrollbar = ttk.Scrollbar(ports_result_frame, orient="vertical")
ports_y_scrollbar.pack(side="right", fill="y")

ports_x_scrollbar = ttk.Scrollbar(ports_result_frame, orient="horizontal")
ports_x_scrollbar.pack(side="bottom", fill="x")

# Treeview oluşturma
ports_treeview = ttk.Treeview(
    ports_result_frame, 
    columns=("Port", "Servis", "Versiyon", "Durum", "Banner"), 
    show="headings",
    yscrollcommand=ports_y_scrollbar.set,
    xscrollcommand=ports_x_scrollbar.set
)

ports_y_scrollbar.config(command=ports_treeview.yview)
ports_x_scrollbar.config(command=ports_treeview.xview)
ports_treeview.pack(fill="both", expand=True)

# Sütun yapılandırması
ports_treeview.column("Port", width=80, minwidth=80)
ports_treeview.column("Servis", width=100, minwidth=100)
ports_treeview.column("Versiyon", width=180, minwidth=150)
ports_treeview.column("Durum", width=100, minwidth=100)
ports_treeview.column("Banner", width=500, minwidth=300, stretch=True)

ports_treeview.heading("Port", text="Port")
ports_treeview.heading("Servis", text="Servis")
ports_treeview.heading("Versiyon", text="Versiyon")
ports_treeview.heading("Durum", text="Durum")
ports_treeview.heading("Banner", text="Banner")

# Zebra desenli satırlar için tag'ler
ports_treeview.tag_configure('oddrow', background='#f9f9f9')
ports_treeview.tag_configure('evenrow', background='white')
ports_treeview.tag_configure('open', foreground=COLORS["success"], font=("Segoe UI", 9, "bold"))
ports_treeview.tag_configure('closed', foreground=COLORS["danger"])
ports_treeview.tag_configure('filtered', foreground=COLORS["warning"])

# İlerleme çubuğu için frame (daha şık görünüm)
progress_frame = ttk.LabelFrame(network_results_frame, text="Tarama İlerlemesi")
progress_frame.pack(fill="x", padx=10, pady=10)

progress_info_frame = ttk.Frame(progress_frame, padding=10)
progress_info_frame.pack(fill="x", expand=True)

scan_progress = ttk.Progressbar(progress_info_frame, mode='determinate', length=100, style="Horizontal.TProgressbar")
scan_progress.pack(fill="x", padx=10, pady=5)
scan_progress_label = ttk.Label(progress_info_frame, text="Henüz tarama yapılmadı", font=("Segoe UI", 9))
scan_progress_label.pack(pady=5, anchor="center")

# Sonuçları dışa aktarma fonksiyonu
def export_network_results():
    # Treeview içeriğini al
    all_results = []
    all_results.append(f"Network Tarama Sonuçları - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    all_results.append(f"Hedef: {network_target_entry.get()}\n")
    
    # OS bilgisi
    os_text = os_info_treeview.get(os_info_treeview.selection()[0], "values")[1]
    all_results.append(f"İşletim Sistemi: {os_text}\n")
    
    # Port bilgileri
    all_results.append("Port Bilgileri:")
    all_results.append("Port\tServis\tVersiyon\tDurum\tBanner")
    
    for item_id in ports_treeview.get_children():
        item_values = ports_treeview.item(item_id, "values")
        all_results.append("\t".join(str(val) for val in item_values))
    
    # Dışa aktar
    content = "\n".join(all_results)
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Network Tarama Sonuçlarını Dışa Aktar"
    )
        
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)
        messagebox.showinfo("Başarılı", f"Sonuçlar {file_path} konumuna kaydedildi.")

# TreeView'a çift tıklama eventi ekleyin (import bölümünden sonra, start_network_scan fonksiyonundan önce ekleyin)
def show_port_details(event):
    """TreeView satırına çift tıklandığında ayrıntılı bilgi gösterecek fonksiyon"""
    if not ports_treeview.selection():
        return
        
    item = ports_treeview.selection()[0]
    port_values = ports_treeview.item(item, "values")
    
    if not port_values:
        return
    
    # Detay penceresi oluştur
    detail_window = tk.Toplevel(pencere)
    detail_window.title(f"Port {port_values[0]} Detayları")
    detail_window.geometry("800x600")  # Daha büyük pencere
    detail_window.minsize(700, 500)
    
    # Pencereyi ana pencereye göre ortala
    w = 800
    h = 600
    ws = pencere.winfo_screenwidth()
    hs = pencere.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    detail_window.geometry('%dx%d+%d+%d' % (w, h, x, y))
    
    # Stil
    detail_window.configure(bg=COLORS["light_bg"])
    
    # İçerik çerçevesi
    content_frame = ttk.Frame(detail_window, padding=15)
    content_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Başlık
    port_status = port_values[3]
    status_color = COLORS["success"] if port_status == "AÇIK" else COLORS["danger"] if port_status == "KAPALI" else COLORS["warning"]
    
    ttk.Label(
        content_frame, 
        text=f"Port {port_values[0]} ({port_values[1]}) - {port_status}", 
        font=("Segoe UI", 14, "bold"),
        foreground=status_color
    ).pack(anchor="w", pady=(0, 15))
    
    # Bilgi bölümü - Port, Servis ve Versiyon
    info_frame = ttk.Frame(content_frame)
    info_frame.pack(fill="x", expand=False, pady=5)
    
    ttk.Label(info_frame, text=f"PORT: {port_values[0]}", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 20), pady=2)
    ttk.Label(info_frame, text=f"SERVİS: {port_values[1]}", font=("Segoe UI", 10, "bold")).grid(row=0, column=1, sticky="w", padx=(0, 20), pady=2)
    ttk.Label(info_frame, text=f"DURUM: {port_values[3]}", font=("Segoe UI", 10, "bold"), foreground=status_color).grid(row=0, column=2, sticky="w", pady=2)
    ttk.Label(info_frame, text=f"VERSİYON: {port_values[2]}", font=("Segoe UI", 10)).grid(row=1, column=0, columnspan=3, sticky="w", pady=2)
    
    # Banner bilgisi başlık
    ttk.Label(content_frame, text="BANNER BİLGİSİ:", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(15, 5))
    
    # Detayları içeren scrollable Text widget
    banner_frame = ttk.Frame(content_frame)
    banner_frame.pack(fill="both", expand=True, pady=5)
    
    # Scrollbar'lar
    banner_y_scrollbar = ttk.Scrollbar(banner_frame, orient="vertical")
    banner_y_scrollbar.pack(side="right", fill="y")
    
    banner_x_scrollbar = ttk.Scrollbar(banner_frame, orient="horizontal")
    banner_x_scrollbar.pack(side="bottom", fill="x")
    
    details_text = tk.Text(banner_frame, wrap="none", height=20, 
                          yscrollcommand=banner_y_scrollbar.set,
                          xscrollcommand=banner_x_scrollbar.set,
                          font=("Consolas", 10))  # Monospace font
    details_text.pack(fill="both", expand=True)
    
    banner_y_scrollbar.config(command=details_text.yview)
    banner_x_scrollbar.config(command=details_text.xview)
    
    # Banner bilgisini ekle
    banner = port_values[4]
    if banner:
        # Sözlük formatını kontrol et (kırpılmış olabilir)
        if banner.startswith('{') and (banner.endswith('}') or '...' in banner):
            try:
                # Eğer banner bir sözlükse ve '...' ile kırpılmışsa, bunları temizleyelim
                clean_banner = banner.replace("'", '"').replace("...", "")
                
                if clean_banner.endswith("}"):
                    # JSON formatına çevirmeye çalış
                    import json
                    try:
                        banner_dict = json.loads(clean_banner)
                        # Güzel formatlanmış sözlük
                        formatted_banner = json.dumps(banner_dict, indent=4)
                        details_text.insert("1.0", formatted_banner)
                    except:
                        # JSON formatına çevrilemiyorsa orijinal haliyle göster
                        details_text.insert("1.0", banner)
                else:
                    # Normal metin olarak göster
                    details_text.insert("1.0", banner)
            except:
                # Herhangi bir hata durumunda orijinal metni göster
                details_text.insert("1.0", banner)
        else:
            # Normal metin
            details_text.insert("1.0", banner)
    else:
        details_text.insert("1.0", "Banner bilgisi bulunamadı.")
    
    # Metni renklendir (opsiyonel)
    details_text.tag_configure("key", foreground="blue")
    details_text.tag_configure("value", foreground="dark green")
    
    # Salt okunur yap
    details_text.config(state="disabled")
    
    # Dışa aktar butonu
    def export_banner():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Banner Bilgisini Dışa Aktar"
        )
        
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(banner)
            messagebox.showinfo("Başarılı", f"Banner bilgisi {file_path} konumuna kaydedildi.")
    
    button_frame = ttk.Frame(content_frame)
    button_frame.pack(fill="x", pady=10)
    
    ttk.Button(
        button_frame,
        text="Dışa Aktar",
        command=export_banner
    ).pack(side=tk.LEFT, padx=5)
    
    ttk.Button(
        button_frame,
        text="Kapat", 
        command=detail_window.destroy
    ).pack(side=tk.RIGHT, padx=5)

# TreeView'a çift tıklama eventi bağla
ports_treeview.bind("<Double-1>", show_port_details)

# Network tarama fonksiyonu
def start_network_scan():
    target = network_target_entry.get()
    if not target:
        messagebox.showwarning("Uyarı", "Lütfen bir domain veya IP adresi girin.")
        return
    
    # Port listesini al
    try:
        port_text = ports_entry.get()
        if port_text:
            ports = [int(p.strip()) for p in port_text.split(",")]
        else:
            ports = [21, 22, 25, 80, 443, 3306, 8080]  # Varsayılan portlar
    except:
        messagebox.showwarning("Uyarı", "Geçersiz port formatı. Örnek: 80,443,8080")
        return
    
    # Seçilen tarama türlerini kontrol et
    if not any([quick_scan_var.get(), syn_scan_var.get(), service_detect_var.get()]):
        messagebox.showwarning("Uyarı", "En az bir tarama türü seçmelisiniz.")
        return
    
    # Verileri temizle
    ports_treeview.delete(*ports_treeview.get_children())
    os_info_treeview.delete(*os_info_treeview.get_children())
    
    # İlerlemeyi göster
    scan_progress["value"] = 0
    scan_progress_label.config(text="Tarama hazırlanıyor...")
    scan_progress.pack(fill="x", padx=10, pady=10)
    
    # Tarama butonunu devre dışı bırak
    scan_button.config(state="disabled", text="Taranıyor...")
    
    def scan_callback(results):
        # OS bilgisini güncelle
        os_info_treeview.delete(*os_info_treeview.get_children())
        
        # SYN taraması için özel değer atama
        if "syn_results" in results and not "services" in results:
            os_info_treeview.insert("", "end", 
                                 values=("SYN Taraması", "SYN taraması ile işletim sistemi tespit edilemez", ""), 
                                 tags=('evenrow',))
        # Genel OS bilgisi
        elif "os" in results:
            os_info = results["os"]
            confidence = "Orta"
            confidence_tag = 'medium'
            
            if "TTL:" in os_info:
                source = "TTL Analizi"
            else:
                source = "Genel Analiz"
            
            os_info_treeview.insert("", "end", 
                                values=(source, os_info, confidence), 
                                tags=('evenrow', confidence_tag))
        
        # Portlardan gelen OS bilgilerini ekle
        row_count = 1
        os_hints = {}
        
        # Servis tespiti sonuçlarından OS ipuçlarını topla
        if "services" in results:
            for port, service_info in results["services"].items():
                service_name = service_info.get("name", "")
                banner = service_info.get("banner", "")
                version = service_info.get("version", "")
                
                os_hint = None
                confidence = "Düşük"
                confidence_tag = 'low'
                source = f"Port {port} ({service_name})"
                
                # SSH banner analizi
                if service_name == "SSH" and version:
                    if "ubuntu" in version.lower():
                        os_hint = "Ubuntu Linux"
                        confidence = "Yüksek"
                        confidence_tag = 'high'
                    elif "debian" in version.lower():
                        os_hint = "Debian Linux"
                        confidence = "Yüksek" 
                        confidence_tag = 'high'
                    elif "windows" in version.lower():
                        os_hint = "Windows Server"
                        confidence = "Yüksek"
                        confidence_tag = 'high'
                    elif "openssh" in version.lower():
                        os_hint = "Unix/Linux"
                        confidence = "Orta"
                        confidence_tag = 'medium'
                
                # HTTP/HTTPS servisleri için
                elif service_name in ["HTTP", "HTTPS"] and banner:
                    if "IIS" in banner:
                        os_hint = "Windows Server"
                        confidence = "Yüksek"
                        confidence_tag = 'high'
                    elif "Apache" in banner:
                        os_hint = "Muhtemelen Linux/Unix"
                        confidence = "Orta"
                        confidence_tag = 'medium'
                    elif "nginx" in banner:
                        os_hint = "Muhtemelen Linux/Unix"
                        confidence = "Orta"
                        confidence_tag = 'medium'
                
                # FTP servisi için
                elif service_name == "FTP" and version:
                    if any(x in version.lower() for x in ['windows', 'microsoft']):
                        os_hint = "Muhtemelen Windows"
                        confidence = "Orta"
                        confidence_tag = 'medium'
                    elif any(x in version.lower() for x in ['unix', 'linux', 'ubuntu', 'debian']):
                        os_hint = "Muhtemelen Linux/Unix"
                        confidence = "Orta"
                        confidence_tag = 'medium'
                
                # Tespit edildiyse ve daha önce eklenmediyse ekle
                if os_hint and f"{source}-{os_hint}" not in os_hints:
                    tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                    os_info_treeview.insert("", "end", 
                                            values=(source, os_hint, confidence), 
                                            tags=(tag, confidence_tag))
                    os_hints[f"{source}-{os_hint}"] = True
                    row_count += 1
        
        # OS bilgisi bulunamadıysa bilgi ver
        if os_info_treeview.get_children() == ():
            os_info_treeview.insert("", "end", 
                                 values=("Bilgi Yok", "İşletim sistemi belirlenemedi", ""), 
                                 tags=('evenrow',))
        
        # Port bilgilerini güncelle
        ports_treeview.delete(*ports_treeview.get_children())
        row_count = 0
        
        # SYN tarama sonuçları için - TAMAMEN AYRI İŞLEME MANTIĞI
        if "syn_results" in results and not "services" in results:
            for port, status in results["syn_results"].items():
                tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                status_tags = [tag]
                
                if "AÇIK" in status:
                    status_tags.append('open')
                    ports_treeview.insert("", "end", 
                                    values=(port, "SYN Taraması", "SYN ile alınamaz", status, "SYN taraması banner bilgisi almaz"), 
                                    tags=tuple(status_tags))
                elif "KAPALI" in status:
                    status_tags.append('closed')
                    ports_treeview.insert("", "end", 
                                    values=(port, "SYN Taraması", "SYN ile alınamaz", status, "SYN taraması banner bilgisi almaz"), 
                                    tags=tuple(status_tags))
                else:
                    status_tags.append('filtered')
                    ports_treeview.insert("", "end", 
                                    values=(port, "SYN Taraması", "SYN ile alınamaz", status, "SYN taraması banner bilgisi almaz"), 
                                    tags=tuple(status_tags))
                
                row_count += 1
        # Servis tespiti sonuçları için
        elif "services" in results:
            for port, service_info in results["services"].items():
                # Eğer bu port SYN taramasında zaten eklenmişse, güncelle
                existing_item = None
                for item_id in ports_treeview.get_children():
                    if ports_treeview.item(item_id, "values")[0] == str(port):
                        existing_item = item_id
                        break
                
                if existing_item:
                    ports_treeview.delete(existing_item)
                
                tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                status_tags = [tag]
                
                service_name = service_info.get("name", "Bilinmiyor")
                service_version = service_info.get("version", "Bilinmiyor")
                status = service_info.get("status", "AÇIK")
                banner = service_info.get("banner", "")
                
                # Durum tag'ini ekle
                if status == "AÇIK":
                    status_tags.append('open')
                elif status == "KAPALI":
                    status_tags.append('closed')
                else:
                    status_tags.append('filtered')
                
                ports_treeview.insert("", "end", 
                                    values=(port, service_name, service_version, status, banner), 
                                    tags=tuple(status_tags))
                
                row_count += 1
        
        # Tarama tamamlandığında
        scan_progress["value"] = 100
        scan_progress_label.config(text="Tarama tamamlandı")
        scan_button.config(state="normal", text="TARAMA BAŞLAT")
        status_bar.config(text=f"Network taraması tamamlandı: {target}")
    
    def update_progress(percent, message):
        scan_progress["value"] = percent
        scan_progress_label.config(text=message)
        status_bar.config(text=message)
    
    def perform_scan():
        results = {}
        
        try:
            # SYN tarama
            if syn_scan_var.get() and not service_detect_var.get() and not quick_scan_var.get():
                update_progress(20, "SYN port taraması yapılıyor...")
                syn_results = syn_port_scan(target, ports)
                results["syn_results"] = syn_results
                # SYN taraması için varsayılan işletim sistemi bilgisi
                # results["os"] = "SYN taramasıyla tespit edilemez" - gereksiz

            # Servis tespiti
            elif service_detect_var.get():
                update_progress(50, "Servis tespiti yapılıyor...")
                service_results = detect_services_for_open_ports(target, ports)
                results.update(service_results)
            
            # Hızlı tarama (OS ve servis tespiti)
            elif quick_scan_var.get():
                update_progress(60, "Hızlı tarama yapılıyor...")
                quick_results = detect_os_and_versions(target, ports)
                results.update(quick_results)
            
            return results
        
        except Exception as e:
            return {"error": str(e)}
    
    # Asenkron çalıştır
    run_async(perform_scan, scan_callback)

# Tarama butonuna komut ekle
scan_button.config(command=start_network_scan)

# Global değişkenler
current_vulnerabilities = []  # Arama sonuçlarını saklamak için

def detail_column_click(event):
    region = vuln_treeview.identify("region", event.x, event.y)
    if region == "cell":
        column = vuln_treeview.identify_column(event.x)
        if column == "#5":  # Detay sütunu
            show_vuln_details(None)

# Tıklama eventi için bağlantı
vuln_treeview.bind("<ButtonRelease-1>", detail_column_click)

# KVKK Veri İhlali sekmesine eklenecek fonksiyonlar:

def run_spider_with_query(query):
    """
    Verilen sorguyla scrapy spider'ı çalıştırır
    """
    try:
        # Komut çalıştırmadan önce dizini kontrol et
        spider_dir = os.path.join(os.path.dirname(__file__), "KvkkVeriIhlali", "vericrawler")
        
        if not os.path.exists(spider_dir):
            os.makedirs(os.path.dirname(os.path.join(spider_dir, "bilgi.json")), exist_ok=True)
            messagebox.showwarning("Uyarı", f"Spider dizini oluşturuldu: {spider_dir}")
            
        # JSON dosyasının tam yolu
        json_path = os.path.join(spider_dir, "bilgi.json")
        
        # Scrapy komutunu hazırla
        command = f'cd "{spider_dir}" && scrapy crawl SearchCrawler -a arama_kelimesi="{query}" -O bilgi.json'
        
        # Durum çubuğunu güncelle
        status_bar.config(text=f"Veri ihlal bildirimlerini arıyor: {query}...")
        
        # Komutu çalıştır
        process = subprocess.Popen(
            command, 
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Sonucu bekle
        stdout, stderr = process.communicate()
        
        # Hata kontrolü
        if process.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='ignore')
            messagebox.showerror("Hata", f"Spider çalıştırılamadı:\n{error_msg}")
            status_bar.config(text="Arama hatası! Spider çalıştırılamadı.")
            return False
            
        # Başarılı ise geriye True döndür
        status_bar.config(text=f"Veri ihlal bildirimleri başarıyla alındı. Temizleniyor...")
        return True
        
    except Exception as e:
        messagebox.showerror("Hata", f"Spider çalıştırırken bir hata oluştu:\n{str(e)}")
        status_bar.config(text="Hata! Arama yapılamadı.")
        return False

# Veri İhlali sekmesindeki arama butonu fonksiyonunu yeniden tanımla
def search_breach_from_web():
    query = breach_search_entry.get().strip()
    
    if not query:
        messagebox.showwarning("Uyarı", "Lütfen bir arama sorgusu girin.")
        return
    
    # Arama butonunu devre dışı bırak
    breach_search_button.config(state="disabled", text="Aranıyor...")
    
    def process_results():
        # Spider'ı çalıştır
        if run_spider_with_query(query):
            # Temizleme işlemini çalıştır
            global breach_data
            breach_data = veri_temizle_ve_analiz_et()
            
            # Sonuçları göster
            search_breach_data()
            
            # İstatistikler çıkar
            ihlal_sayisi = sum(1 for item in breach_data if item.get("veri_ihlali_mi", False))
            toplam_etkilenen = sum(int(item.get("kisi_sayisi", "0").replace(".", "").replace(",", "")) 
                              for item in breach_data 
                              if item.get("kisi_sayisi") and item.get("veri_ihlali_mi", False))
            
            # Durum çubuğunu güncelle
            status_bar.config(text=f"Veri ihlal bildirimi araması tamamlandı: {query} - {ihlal_sayisi} ihlal bildirimi, toplam {toplam_etkilenen:,} etkilenen kişi".replace(",", "."))
        
        # Arama butonunu normal durumuna getir
        breach_search_button.config(state="normal", text="ARA")
    
    # İşlemi arka planda çalıştır
    run_async(process_results)

# Arama butonuna yeni fonksiyonu bağla (Veri İhlali sekmesindeki kod içinde)
breach_search_button.config(command=search_breach_from_web)

# Ana döngüyü başlat
pencere.mainloop()
