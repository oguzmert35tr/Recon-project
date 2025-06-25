# Recon & Vulnerability Scanner

**Recon & Vulnerability Scanner**, web uygulamalarındaki yaygın güvenlik açıklarını otomatik olarak tespit etmek için geliştirilmiş Python tabanlı bir araçtır.
Bu proje, özellikle OWASP Juice Shop gibi eğitim amaçlı uygulamalarda kullanılmak üzere SQL Injection, XSS, IDOR ve Security Misconfiguration gibi zafiyetleri tarar.

---

## Özellikler

- **SQL Injection Taraması**  
  - Yetkisiz ve JWT ile yetkili tarama seçenekleri  
- **Cross-Site Scripting (XSS) Tespiti**  
- **IDOR (Insecure Direct Object Reference) Testleri**  
- **Security Misconfiguration Kontrolleri**  
  - HTTP Güvenlik Header eksiklikleri  
  - TLS sürümü ve güvenlik kontrolü  
- **Detaylı Raporlama**  
  - Tespit edilen açıklar dosyalara kaydedilir  
  - Özet ve istatistiksel çıktı sağlar  

---

## Kurulum

Projeyi klonlayıp bağımlılıkları yüklemek için:


git clone git@github.com:oguzmert35tr/Recon-project.git
cd Recon-project
python3 -m venv venv
source venv/bin/activate   # Linux / Mac
# Windows için:
# venv\Scripts\activate
pip install -r requirements.txt
Recon-project/
├── main.py                  # Ana program dosyası
├── scanner/                 # Tarama modülleri
│   ├── sql_injection.py
│   ├── sqlmap_auth_scan.py
│   ├── xss_scanner.py
│   ├── idor_scanner.py
│   ├── security_misconfig.py
│   └── __init__.py
├── urls.txt                 # Test edilecek URL listesi
├── requirements.txt         # Proje bağımlılıkları
└── README.md                # Proje açıklaması ve kullanım bilgisi
