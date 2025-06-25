import subprocess
import os

def run():
    print("[*] ParamSpider ile endpointler parametreli olarak taranıyor...\n")
    
    output_file = "scanner/urls.txt"
    target_url = "http://localhost:9000"

    try:
        subprocess.run([
            "python3", "paramspider/paramspider_scanner.py",
            "-d", target_url,
            "--level", "high",
            "-o", output_file
        ], check=True)
        
        print(f"[*] Parametreli endpointler '{output_file}' dosyasına kaydedildi.")
    except subprocess.CalledProcessError:
        print("[!] ParamSpider çalıştırılırken hata oluştu.")

