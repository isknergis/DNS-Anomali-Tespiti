from scapy.all import sniff, DNSQR,IP
from datetime import datetime,timedelta

#IPlere göre sorguları kaydedeceğimiz yer.
sorgu_kayitlari={}

#Kaç saniyelik zaman diliminde, kaç sorgudan fazla olursa şüpheli
ZAMAN_PENCERESI =10 # saniye
SINIR =15 #Bu kadar sorgudan fazlası anormal olabilir.
def dns_anomali_kontrol(paket):
	if paket.haslayer(DNSQR):
		zaman=datetime.now()
		ip=paket[IP].src
		
		#Liste yoksa başlat
		
		if ip not in sorgu_kayitlari:
			sorgu_kayitlari[ip]=[]
		
		#IP için yeni zaman kaydı
		sorgu_kayitlari[ip].append(zaman)
		
		#Eski kayıtları temizle(örneğin 10 saniyeden öncesi)
		sorgu_kayitlari[ip]=[t for t in sorgu_kayitlari[ip] if zaman -t < timedelta(seconds=ZAMAN_PENCERESI)]
		
		#şüpheli mi
		if len (sorgu_kayitlari[ip]) > SINIR:
			print(f"[{zaman}] ŞÜPHELİ DNS TRAFİĞİ : {ip} son {ZAMAN_PENCERESI} sn içinde {len(sorgu_kayitlari[ip])} sorgu gönderdi")
			
print("DNS Anomali Tespiti Başladı... (Çıkmak için Ctrl+C)")
sniff(filter="udp port 53", prn=dns_anomali_kontrol, store=0)
