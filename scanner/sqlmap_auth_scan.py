import subprocess
import time
import os
import json

def run():
    urls_file = "scanner/urls.txt"
    vulnerable_urls_file = "scanner/vulnerable_urls_auth.txt"
    detailed_results_file = "scanner/sqlmap_detailed_results_auth.txt"
    config_file = "scanner/config.json"

    # 1. JWT token'ı config dosyasından al
    if not os.path.exists(config_file):
        print(f"[!] JWT token içeren config dosyası bulunamadı: {config_file}")
        return

    try:
        with open(config_file, "r") as f:
            config = json.load(f)
            jwt_token = config.get("jwt_token", "").strip()
    except Exception as e:
        print(f"[!] config.json dosyası okunamadı: {e}")
        return

    if not jwt_token.startswith("Bearer "):
        print("[!] JWT token formatı hatalı. 'Bearer ' ile başlamalı.")
        return

    print("[*] SQLMap (JWT ile Yetkili) taraması başlatılıyor...")

    # 2. URL listesini oku
    if not os.path.exists(urls_file):
        print(f"[!] URL dosyası bulunamadı: {urls_file}")
        return

    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print("[!] URL listesi boş.")
        return

    # 3. Önceki çıktıları temizle
    for output_file in [vulnerable_urls_file, detailed_results_file]:
        open(output_file, "w").close()

    total_urls = len(urls)
    vulnerable_count = 0
    start_time = time.time()

    # 4. Taramaya başla
    for i, url in enumerate(urls, start=1):
        print(f"\n[{i}/{total_urls}] Taranıyor (auth): {url}")

        headers_value = f"Authorization: {jwt_token}"

        try:
            result = subprocess.run([
                "sqlmap",
                "-u", url,
                "--batch",
                "--level", "3",
                "--risk", "2",
                "--random-agent",
                "--timeout=30",
                "--retries=2",
                "--crawl=1",
                f"--headers={headers_value}"
            ], capture_output=True, text=True, timeout=120)

            output = result.stdout

            # 5. Zafiyet kontrolü
            if "is vulnerable" in output or "parameter" in output.lower():
                print(f"[+] Zafiyet bulundu: {url}")
                vulnerable_count += 1

                with open(vulnerable_urls_file, "a") as vuln_file:
                    vuln_file.write(url + "\n")

                with open(detailed_results_file, "a") as detail_file:
                    detail_file.write("=" * 80 + "\n")
                    detail_file.write(f"VULNERABLE: {url}\n")
                    detail_file.write(output + "\n")

            else:
                print(f"[-] Zafiyet bulunamadı: {url}")

        except subprocess.TimeoutExpired:
            print(f"[!] Zaman aşımı: {url}")
            with open(detailed_results_file, "a") as detail_file:
                detail_file.write("=" * 80 + "\n")
                detail_file.write(f"TIMEOUT: {url}\n")

        except Exception as e:
            print(f"[!] Hata oluştu: {url} => {e}")

        # 6. Her istekte küçük bekleme (rate limit koruması için)
        time.sleep(1)

    # 7. Özet
    elapsed = time.time() - start_time
    percentage = (vulnerable_count / total_urls) * 100

    print("\n" + "=" * 60)
    print(f"[*] Tarama tamamlandı (Yetkili).")
    print(f"[*] Toplam URL: {total_urls}")
    print(f"[*] Zafiyet bulunan URL: {vulnerable_count}")
    print(f"[*] Tespit oranı: %{percentage:.2f}")
    print(f"[*] Toplam süre: {elapsed:.2f} saniye")
    print(f"[*] Zafiyetli URL'ler: {vulnerable_urls_file}")
    print(f"[*] Detaylı çıktılar: {detailed_results_file}")
    print("=" * 60)

if __name__ == "__main__":
    run()


