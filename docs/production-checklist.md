# Üretim Kontrol Listesi

## Genel Bakış

Bu kontrol listesi, bir ajan sistemini üretime almadan önce doğrulanması gereken güvenlik kontrollerini kapsar. Her kontrol, risk seviyesi ve ilgili doküman referansı ile birlikte sunulur.

---

## 1. Girdi ve Prompt Güvenliği

- [ ] **Prompt injection filtreleri aktif** — Bilinen saldırı kalıpları için regex tabanlı filtreler yapılandırılmış
- [ ] **Talimat/veri ayrımı uygulanmış** — Kullanıcı girdisi ve dış içerik net delimiter'larla ayrılmış
- [ ] **Anti-extraction talimatları** — Sistem prompt'unda çıkarma girişimlerini engelleyen talimatlar var
- [ ] **Dış içerik etiketleme** — E-posta, web, belge içerikleri "veri" olarak etiketlenmiş
- [ ] **Kodlanmış injection koruması** — Base64, ROT13, Unicode injection tespiti aktif

→ [Detay: Prompt Injection Savunması](prompt-injection.md)

---

## 2. Araç Güvenliği

- [ ] **Araç allowlist tanımlı** — Ajana sadece gereken araçlar verilmiş
- [ ] **Parametre doğrulama aktif** — Her araç parametresi Pydantic şemasıyla doğrulanıyor
- [ ] **Tehlikeli aksiyon sınıflandırması** — Araçlar risk seviyesine göre sınıflandırılmış
- [ ] **Rate limiting yapılandırılmış** — Araç başına çağrı limitleri belirlenmiş
- [ ] **Araç güvenlik duvarı aktif** — Tüm araç çağrıları merkezi kontrolden geçiyor
- [ ] **Yapılandırılmış çıktı zorunlu** — Ajan çıktısı serbest metin değil, şema doğrulamalı

→ [Detay: Araç Güvenliği](tool-security.md)

---

## 3. Veri Güvenliği

- [ ] **Giden veri politikaları tanımlı** — Hangi verinin hangi kanala çıkabileceği belirlenmiş
- [ ] **PII maskeleme aktif** — TC kimlik, kredi kartı, telefon, e-posta otomatik maskeleniyor
- [ ] **Sır maskeleme aktif** — API anahtarları, token'lar, parolalar maskeleniyor
- [ ] **Hedef engelleme listesi** — Bilinen kötü niyetli alan adları engellenmiş
- [ ] **Veri boyutu limitleri** — Giden veri boyutu sınırlandırılmış
- [ ] **Çıktı izleme aktif** — Tüm ajan çıktıları hassas veri tespiti için izleniyor

→ [Detay: Veri Sızıntısı Önleme](data-exfiltration.md)

---

## 4. Kimlik ve Yetki

- [ ] **Ayrı ajan kimliği** — Her ajan kendi benzersiz kimliğine sahip
- [ ] **Delegasyon modeli** — Taklit değil, kapsamlı delegasyon kullanılıyor
- [ ] **Kısa ömürlü token'lar** — Token süresi dakika/saat düzeyinde
- [ ] **Kullanım limitleri** — Token başına maksimum kullanım sayısı belirlenmiş
- [ ] **Token iptal mekanizması** — Token'lar anında geri alınabiliyor
- [ ] **En az yetki uygulanmış** — Her ajan sadece gereken scope'lara sahip

→ [Detay: Kimlik ve Delegasyon](identity-and-delegation.md)

---

## 5. Bellek Güvenliği

- [ ] **Bellek yazma kontrolü** — Tüm bellek yazmaları güvenlik kontrolünden geçiyor
- [ ] **Kaynak etiketleme** — Her bellek girişinin kaynağı ve güvenilirlik seviyesi belirlenmiş
- [ ] **Injection kalıp tespiti** — Bellek injection kalıpları otomatik tespit ediliyor
- [ ] **Sınırlı ömür** — Bellek girişleri zaman sınırlamasına tabi
- [ ] **Periyodik temizlik** — Güvenilmeyen ve süresi dolmuş girişler düzenli temizleniyor
- [ ] **Bellek denetimi** — Bellek bütünlüğü periyodik olarak kontrol ediliyor

→ [Detay: Bellek ve Bağlam Güvenliği](memory-poisoning.md)

---

## 6. Denetim ve Loglama

- [ ] **Correlation ID oluşturuluyor** — Her istek benzersiz ID ile izleniyor
- [ ] **Tüm araç çağrıları loglanıyor** — Araç adı, parametreler, sonuç loglanıyor
- [ ] **Karar izleri kaydediliyor** — Ajan kararlarının gerekçeleri loglanıyor
- [ ] **Politika kontrolleri loglanıyor** — İzin/red kararları ve nedenleri loglanıyor
- [ ] **Onay kararları loglanıyor** — Onay talepleri ve yanıtları loglanıyor
- [ ] **Yapılandırılmış log formatı** — JSON formatında, makine okunabilir loglar
- [ ] **Zincirlenmiş hash** — Log bütünlüğü kriptografik hash ile korunuyor
- [ ] **Hassas veri maskeleme** — Loglarda PII ve sırlar maskeleniyor
- [ ] **Log saklama politikası** — Düzenleyici gereksinimlere uygun saklama süresi

→ [Detay: Denetim ve Hesap Verebilirlik](audit-and-accountability.md)

---

## 7. İnsan Onayı ve Yönetişim

- [ ] **Risk kademelendirme tanımlı** — Aksiyonlar risk seviyesine göre sınıflandırılmış
- [ ] **Onay akışları aktif** — Yüksek riskli aksiyonlar onay gerektiriyor
- [ ] **Açıkla-sonra-yap kalıbı** — Ajan, aksiyonu önce kullanıcıya açıklıyor
- [ ] **Zaman aşımı** — Onay talepleri belirli sürede yanıtlanmazsa reddediliyor
- [ ] **Aşamalı doğrulama** — Kritik aksiyonlar ek doğrulama gerektiriyor
- [ ] **Politika hiyerarşisi** — Organizasyon politikaları kullanıcı tercihleri üzerinde

→ [Detay: İnsan Onayı ve Yönetişim](hitl-governance.md)

---

## 8. Altyapı Güvenliği

- [ ] **Sır yönetimi** — API anahtarları ve kimlik bilgileri güvenli vault'ta
- [ ] **Ağ segmentasyonu** — Bileşenler ayrı ağ segmentlerinde
- [ ] **API gateway** — Tüm araç çağrıları merkezi gateway üzerinden
- [ ] **mTLS** — Servisler arası şifreli iletişim
- [ ] **Egress kontrolü** — Dış ağa çıkan trafik kısıtlı ve izlenen
- [ ] **İzole araç çalıştırma** — Araçlar container/sandbox'ta çalışıyor
- [ ] **Sır rotasyonu** — Anahtarlar ve token'lar periyodik olarak değiştiriliyor

→ [Detay: Dağıtım ve Altyapı Güvenliği](deployment-security.md)

---

## 9. Test ve Doğrulama

- [ ] **Bilinen injection kalıplarıyla test** — Standart saldırı vektörleri test edilmiş
- [ ] **Araç kötüye kullanım testi** — Yetkisiz araç çağrıları denenmiş
- [ ] **Veri sızıntısı testi** — Hassas verinin dışarı çıkıp çıkmadığı test edilmiş
- [ ] **Onay akışı testi** — Onay mekanizmalarının düzgün çalıştığı doğrulanmış
- [ ] **Rate limit testi** — Çağrı limitlerinin uygulandığı test edilmiş
- [ ] **Log bütünlük testi** — Log zincirinin doğru oluştuğu doğrulanmış
- [ ] **Delegasyon testi** — Token scope'larının doğru uygulandığı test edilmiş

---

## 10. Operasyonel Hazırlık

- [ ] **İzleme panosu** — Ajan metrikleri ve güvenlik alarmları görünür
- [ ] **Alarm kuralları** — Anomali tespiti için eşik değerler tanımlı
- [ ] **Olay müdahale planı** — Güvenlik olayı durumunda aksiyon planı mevcut
- [ ] **Geri alma planı** — Sorunlu ajan sürümünü geri alma prosedürü mevcut
- [ ] **Kapasite planlaması** — Yük testi ve ölçekleme planı hazır
- [ ] **Dokümantasyon** — Güvenlik mimarisi ve politikalar dokümante edilmiş

---

## Öncelik Sıralaması

| Öncelik | Kontroller | Ne Zaman? |
|---|---|---|
| **P0 — Zorunlu** | Araç allowlist, parametre doğrulama, onay akışı, correlation ID | Üretime geçmeden önce |
| **P1 — Kritik** | PII maskeleme, egress politikası, injection filtresi, delegasyon | İlk hafta içinde |
| **P2 — Önemli** | Bellek koruması, yapılandırılmış çıktı, log hash, izleme | İlk ay içinde |
| **P3 — İyileştirme** | Anomali tespiti, periyodik denetim, gelişmiş test | Sürekli iyileştirme |
