import requests
import time
import os
from collections import Counter
from urllib.parse import urlparse
import socket
import ssl

def check_tls_version(hostname, port=443):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, port))
        tls_version = conn.version()  # Ör: TLSv1.2, TLSv1.3
        conn.close()
        return tls_version
    except Exception as e:
        return f"Hata: {e}"

def run():
    urls_file = "scanner/urls.txt"
    vulnerable_file = "scanner/misconfig_vulnerable.txt"
    no_issues_file = "scanner/misconfig_no_issues.txt"

    if not os.path.exists(urls_file):
        print(f"[!] '{urls_file}' dosyası bulunamadı.")
        return

    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    total = len(urls)
    vulnerable_count = 0
    no_issue_count = 0
    issue_type_counter = Counter()  # Tür bazında sorun sayacı
    start_time = time.time()

    open(vulnerable_file, "w").close()
    open(no_issues_file, "w").close()

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{total}] Test ediliyor: {url}")
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            findings = []

            # Mevcut kontroller
            if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
                findings.append("Eksik veya yanlış X-Content-Type-Options header")

            if "X-Frame-Options" not in headers:
                findings.append("Eksik X-Frame-Options header")

            if "Content-Security-Policy" not in headers:
                findings.append("Eksik Content-Security-Policy header")

            if url.startswith("https://") and "Strict-Transport-Security" not in headers:
                findings.append("Eksik Strict-Transport-Security header")

            if "Server" in headers:
                findings.append(f"Server header bilgisi var")

            if response.status_code >= 400:
                findings.append(f"HTTP hata kodu")

            # Yeni eklenen header kontrolleri:

            # 1. X-Permitted-Cross-Domain-Policies
            if "X-Permitted-Cross-Domain-Policies" not in headers:
                findings.append("Eksik X-Permitted-Cross-Domain-Policies header")

            # 2. Referrer-Policy
            if "Referrer-Policy" not in headers:
                findings.append("Eksik Referrer-Policy header")

            # 3. Cache-Control ve Pragma kontrolü
            cache_control = headers.get("Cache-Control", "").lower()
            pragma = headers.get("Pragma", "").lower()
            if not cache_control and not pragma:
                findings.append("Eksik Cache-Control veya Pragma header")

            # TLS versiyon kontrolü
            parsed = urlparse(url)
            if parsed.scheme == "https":
                tls_version = check_tls_version(parsed.hostname)
                if tls_version.startswith("TLSv1.0") or tls_version.startswith("TLSv1.1") or tls_version.startswith("SSL") or tls_version.startswith("Hata"):
                    findings.append(f"Güvensiz TLS sürümü: {tls_version}")
            else:
                # HTTPS değil, TLS kontrolü yapılmıyor.
                pass

            if findings:
                vulnerable_count += 1

                # Tür bazında sayaç arttır
                for issue in findings:
                    issue_type_counter[issue] += 1

                with open(vulnerable_file, "a") as vf:
                    vf.write(f"{url}\n")
                    for item in findings:
                        vf.write(f" - {item}\n")
                    vf.write("\n")
            else:
                no_issue_count += 1
                with open(no_issues_file, "a") as nf:
                    nf.write(url + "\n")

        except Exception as e:
            print(f"[!] Hata oluştu ({url}): {e}")

    elapsed = time.time() - start_time

    print("\n" + "="*50)
    print("[*] Security Misconfiguration testi tamamlandı.")
    print(f"[*] Toplam URL: {total}")
    print(f"[*] Zafiyet bulunan URL: {vulnerable_count}")
    print(f"[*] Sorunsuz URL: {no_issue_count}")
    print(f"[*] Geçen süre: {elapsed:.2f} saniye")
    print(f"[*] Zafiyetli URL'ler dosyası: {vulnerable_file}")
    print(f"[*] Sorunsuz URL'ler dosyası: {no_issues_file}")

    print("\n[*] Tür bazında tespit edilen sorunlar:")
    for issue, count in issue_type_counter.most_common():
        print(f"  - {issue}: {count} adet")

    print("="*50)

