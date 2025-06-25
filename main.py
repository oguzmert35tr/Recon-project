import os
import scanner.sql_injection as sqli
import scanner.xss_scanner as xss
import scanner.security_misconfig as misconfig
import scanner.idor_scanner as idor

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def print_menu():
    print("=" * 50)
    print(" RECON & VULNERABILITY SCANNER MAIN MENU")
    print("=" * 50)
    print("1. SQL Injection Test (Yetkisiz)")
    print("2. SQL Injection Test (JWT ile Yetkili)")
    print("3. SQL Injection Sonuçları Raporla")
    print("4. XSS Açığı Test Et (urls_xss.txt üzerinden)")
    print("5. Security Misconfiguration Testi")
    print("6. IDOR Testi")
    print("0. Çıkış")
    print("=" * 50)

def main():
    while True:
        clear_screen()
        print_menu()
        choice = input("Seçiminizi girin: ")

        if choice == "1":
            sqli.run(authenticated=False)
        elif choice == "2":
            sqli.run(authenticated=True)
        elif choice == "3":
            os.system("cat scanner/sqlmap_detailed_results.txt")
        elif choice == "4":
            xss.run()
        elif choice == "5":
            misconfig.run()
        elif choice == "6":
            idor.run()
        elif choice == "0":
            print("Çıkılıyor...")
            break
        else:
            print("Geçersiz seçim. Tekrar deneyin.")
        input("\nDevam etmek için Enter tuşuna basın...")

if __name__ == "__main__":
    main()


