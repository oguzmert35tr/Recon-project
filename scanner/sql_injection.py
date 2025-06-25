import subprocess
import time
import os
import requests

def get_jwt_token():
    url = "http://localhost:9000/rest/user/login"
    creds = {"email": "admin@juice-sh.op", "password": "admin123"}
    try:
        resp = requests.post(url, json=creds)
        if resp.status_code == 200:
            token = resp.json().get("authentication", {}).get("token")
            if token:
                print("[*] JWT token alındı.")
                return token
    except Exception as e:
        print(f"[!] Token alma hatası: {e}")
    return None

def run(authenticated=False):
    urls_file = "scanner/urls.txt"
    vulnerable_urls_file = "scanner/vulnerable_urls.txt"
    detailed_results_file = "scanner/sqlmap_detailed_results.txt"
    false_positives_file = "scanner/false_positives.txt"
    clean_urls_file = "scanner/clean_urls.txt"
    timeouts_file = "scanner/timeout_urls.txt"

    for f in [vulnerable_urls_file, detailed_results_file, false_positives_file, clean_urls_file, timeouts_file]:
        open(f, "w").close()

    if not os.path.exists(urls_file):
        print("[!] URL listesi bulunamadı.")
        return

    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    if not urls:
        print("[!] URL listesi boş.")
        return

    total = len(urls)
    vulnerable = 0
    clean = 0
    timeouts = 0
    false_positives = 0
    start_time = time.time()

    token = get_jwt_token() if authenticated else None

    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{total}] Taranıyor: {url}")
        headers = ["--headers", f"Authorization: Bearer {token}"] if authenticated and token else []

        try:
            light_cmd = [
                "sqlmap", "-u", url,
                "--batch", "--level", "1", "--risk", "1",
                "--random-agent", "--crawl=1"
            ] + headers

            light_result = subprocess.run(light_cmd, capture_output=True, text=True, timeout=120)
            light_out = light_result.stdout.lower()

            if "is vulnerable" in light_out or "parameter" in light_out:
                print(f"[+] Hafif taramada şüpheli: {url}")
                # Derin tarama
                deep_cmd = [
                    "sqlmap", "-u", url,
                    "--batch", "--level", "3", "--risk", "2",
                    "--random-agent", "--crawl=1", "--dbs"
                ] + headers
                deep_result = subprocess.run(deep_cmd, capture_output=True, text=True, timeout=300)
                deep_out = deep_result.stdout.lower()

                if "available databases" in deep_out:
                    print(f"[✓] Zafiyet doğrulandı: {url}")
                    vulnerable += 1
                    with open(vulnerable_urls_file, "a") as f:
                        f.write(url + "\n")
                    with open(detailed_results_file, "a") as f:
                        f.write("="*100 + "\n")
                        f.write(f"VULNERABLE: {url}\n")
                        f.write("[*] Hafif Tarama:\n" + light_result.stdout + "\n")
                        f.write("[*] Derin Tarama:\n" + deep_result.stdout + "\n")
                else:
                    print(f"[!] False positive: {url}")
                    false_positives += 1
                    with open(false_positives_file, "a") as f:
                        f.write(url + "\n")
            else:
                print(f"[-] Zafiyet bulunamadı.")
                clean += 1
                with open(clean_urls_file, "a") as f:
                    f.write(url + "\n")
        except subprocess.TimeoutExpired:
            print(f"[!] Zaman aşımı: {url}")
            timeouts += 1
            with open(timeouts_file, "a") as f:
                f.write(url + "\n")
        except Exception as e:
            print(f"[!] Hata: {e}")

    end_time = time.time()
    elapsed = end_time - start_time

    def pct(x): return (x / total) * 100 if total else 0

    print("\n" + "="*60)
    print(f"[*] Tarama tamamlandı.")
    print(f"Toplam URL: {total}")
    print(f"Zafiyet bulunan: {vulnerable} (%{pct(vulnerable):.2f})")
    print(f"False positive: {false_positives} (%{pct(false_positives):.2f})")
    print(f"Temiz (zafiyet yok): {clean} (%{pct(clean):.2f})")
    print(f"Zaman aşımı: {timeouts} (%{pct(timeouts):.2f})")
    print(f"Toplam süre: {elapsed:.2f} saniye")
    print("="*60)


