import json
import os

# Dosya adı ve yolunu tanımla (aynı klasörde olduğu varsayılıyor)
swagger_file = os.path.join(os.path.dirname(__file__), "swagger_docs.json")

# Çalışma dizinini yazdır
print(f"Şu anki çalışma dizini: {os.getcwd()}")
print(f"Açılacak dosya: {swagger_file}")

def extract_endpoints(swagger_path):
    with open(swagger_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    paths = data.get("paths", {})
    extracted = []
    for path, methods in paths.items():
        for method in methods:
            full = f"{method.upper()} {path}"
            extracted.append(full)
    return extracted

# Endpoint'leri çıkart
try:
    endpoints = extract_endpoints(swagger_file)

    # Sonuçları yazdır
    with open("extracted_endpoints.txt", "w", encoding="utf-8") as f:
        for ep in endpoints:
            print(ep)
            f.write(ep + "\n")

    print("\n✔ Endpoint'ler extracted_endpoints.txt dosyasına yazıldı.")

except FileNotFoundError:
    print("❌ Hata: swagger_docs.json dosyası bulunamadı. Lütfen doğru klasörde olduğuna emin olun.")
except json.JSONDecodeError:
    print("❌ Hata: JSON dosyası düzgün formatlanmamış. İçeriğini tekrar kontrol et.")

