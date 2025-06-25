import requests
import re
import time
import os
from collections import defaultdict

def run():
    urls_file = "scanner/urls.txt"
    vulnerable_file = "scanner/idor_vulnerable.txt"
    no_issue_file = "scanner/idor_no_issues.txt"

    if not os.path.exists(urls_file):
        print(f"[!] '{urls_file}' dosyası bulunamadı.")
        return

    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    base_pattern = r"(.*\/)(\d+)(\/?.*)"
    vulnerable_count = 0
    no_issue_count = 0
    start_time = time.time()
    findings = defaultdict(list)

    open(vulnerable_file, "w").close()
    open(no_issue_file, "w").close()

    total_tests = 0

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Test ediliyor: {url}")
        match = re.match(base_pattern, url)
        if not match:
            # ID bulunamadı, atla
            print(" - Sayısal ID bulunamadı, test atlandı.")
            no_issue_count += 1
            with open(no_issue_file, "a") as nf:
                nf.write(url + "\n")
            continue

        base_url = match.group(1)
        current_id = int(match.group(2))
        suffix = match.group(3)

        try:
            # Orijinal URL yanıtı
            original_resp = requests.get(url, timeout=10)
            original_text = original_resp.text

            # Farklı ID’leri dene (current_id-2 ... current_id+2)
            for test_id in range(current_id - 2, current_id + 3):
                if test_id <= 0 or test_id == current_id:
                    continue
                test_url = f"{base_url}{test_id}{suffix}"
                total_tests += 1
                resp = requests.get(test_url, timeout=10)

                # Yanıt farklı mı kontrol et
                if resp.status_code == 200 and resp.text != original_text:
                    print(f" [+] Potansiyel IDOR bulundu! {url} ve {test_url} yanıtları farklı.")
                    findings[url].append(test_url)

            if findings[url]:
                vulnerable_count += 1
                with open(vulnerable_file, "a") as vf:
                    vf.write(f"{url}\n")
                    for v in findings[url]:
                        vf.write(f" - Benzer farklı içerik: {v}\n")
                    vf.write("\n")
            else:
                no_issue_count += 1
                with open(no_issue_file, "a") as nf:
                    nf.write(url + "\n")

        except Exception as e:
            print(f"[!] Hata oluştu ({url}): {e}")
            no_issue_count += 1
            with open(no_issue_file, "a") as nf:
                nf.write(url + "\n")

    elapsed = time.time() - start_time

    print("\n" + "="*50)
    print("[*] IDOR testi tamamlandı.")
    print(f"[*] Toplam URL: {len(urls)}")
    print(f"[*] Toplam test sayısı (varyasyonlar dahil): {total_tests}")
    print(f"[*] Potansiyel zafiyet bulunan URL sayısı: {vulnerable_count}")
    print(f"[*] Sorunsuz URL sayısı: {no_issue_count}")
    print(f"[*] Geçen süre: {elapsed:.2f} saniye")
    print(f"[*] Zafiyetli URL'ler dosyası: {vulnerable_file}")
    print(f"[*] Sorunsuz URL'ler dosyası: {no_issue_file}")
    print("="*50)

