# DNS Anomali Tespit Aracı  
## 📌 Şüpheli DNS Trafiğini İzleme ve Analiz Etme  

🔍 **Bu proje, DNS trafiğini dinleyerek anormal sorgu aktivitelerini tespit eden bir güvenlik aracı sağlamaktadır.**  

---

## 🔍 Özellikler  
Bu sistem aşağıdaki güvenlik işlevlerini yerine getirir:  

- **Gerçek Zamanlı DNS İzleme** → UDP 53 portunu dinleyerek DNS sorgularını analiz eder.  
- **Anormal Trafik Tespiti** → Belirlenen süre içinde aşırı DNS isteği gönderen IP’leri tespit eder.  
- **Eşik Değerine Göre Uyarı** → Belirlenen limitten fazla DNS sorgusu yapan IP’ler ekrana yazdırılır.  
- **Eski Kayıtları Temizleme** → Belirlenen zaman aralığında güncellenmiş veri tutulur.  

