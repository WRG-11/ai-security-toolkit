# AI/LLM Güvenlik Aracı Karşılaştırma Raporu
# Garak vs PyRIT vs NeMo Guardrails

**Tarih:** 2026-05-02
**Ortam:** Windows 11, Ollama (dolphin-mistral, qwen2.5:3b, llama3.2:3b)

---

## 1. Genel Bakış

| Özellik | Garak (NVIDIA) | PyRIT (Microsoft) | NeMo Guardrails (NVIDIA) |
|---------|----------------|--------------------|-----------------------------|
| **Amaç** | Otomatik zafiyet tarama | Red team otomasyon | Programlanabilir koruma |
| **Yaklaşım** | Offensive (saldırı) | Offensive (saldırı) | Defensive (savunma) |
| **Versiyon** | v0.14.1 | v0.13.0 | v0.21.0 |
| **Lisans** | Apache 2.0 | MIT | Apache 2.0 |
| **Dil** | Python | Python | Python + Colang DSL |
| **LLM Desteği** | Ollama, OpenAI, HF | OpenAI-compat | Ollama, OpenAI, HF |
| **Kurulum** | `pip install garak` | `pip install pyrit` | `pip install nemoguardrails` |

## 2. Kapsam Karşılaştırması

### Garak -- Geniş Otomatik Tarama
- **37 kategori, 181+ probe** (aktif)
- Her probe yüzlerce permütasyon üretir (256 varsayılan)
- OWASP LLM Top 10'un ~8/10'unu kapsar
- Tek komutla tam model tarama
- Sonuç: JSONL rapor + HTML özet

**Güçleri:**
- En geniş kapsam -- encoding, dan, promptinject, leakreplay, packagehallucination...
- Otomatik ve tekrarlanabilir
- Tier bazlı model karşılaştırması

**Zayıflıkları:**
- Çok yavaş -- full scan saatler/günler sürebilir
- Probe başı 256 permütasyon genellikle gereksiz fazla
- Başarı tespiti (detector) bazen yanıltıcı
- Ollama ile timeout sorunları (yavaş modeller)

### PyRIT -- Stratejik Red Team
- **5 saldırı stratejisi:** Single-turn, Crescendo, TAP, PAIR, XPIA
- Multi-turn escalation desteği
- Saldırı hafızası (SQLite)
- Programatik saldırı zincirleri

**Güçleri:**
- Multi-turn saldırılar (Crescendo, TAP) -- Garak'ta yok
- Saldırı sonuçlarını hafızada tutar ve analiz eder
- Daha "akıllı" saldırı -- hedefli, adapte olan
- Microsoft'un kendi red team deneyiminden türetilmiş

**Zayıflıkları:**
- Küçük modeller JSON format sorunu (rationale_behind_jailbreak key eksik)
- Ollama entegrasyonu OpenAI-compat üzerinden, bazen uyumsuz
- Daha az probe çeşidi -- stratejik derinlik var ama genişlik yok
- Dokümantasyon karmaşık

### NeMo Guardrails -- Programlanabilir Savunma
- **Colang DSL** ile dialog akış tanımlama
- Input/output rail'leri
- Self-check mekanizması (LLM-based)
- Jailbreak detection rail

**Güçleri:**
- Savunma tarafı -- diğer ikisi saldırı odaklı
- Colang DSL ile okunabilir kural tanımlama
- Modüler rail sistemi -- istediğin korumayı ekle/çıkar
- Prod-ready -- gerçek uygulamalara entegre edilebilir

**Zayıflıkları:**
- Her prompt için 3 LLM çağrısı (input check + response + output check) -- yavaş
- Ollama ile performans sorunu (küçük modeller)
- Self-check sadece LLM kadar iyi -- küçük modeller zayıf
- Colang v1 vs v2 geçiş süreci

## 3. OWASP LLM Top 10 Kapsamı

| OWASP | Garak | PyRIT | NeMo | VulnLLM (Kendi) |
|-------|-------|-------|------|-----------------|
| LLM01 Prompt Injection | ~75 probe | Crescendo, TAP, single | Input rails | 40 teknik + 6 guard |
| LLM02 Info Disclosure | 26 probe | Extraction obj. | Output rails | 20 teknik + PII guard |
| LLM03 Supply Chain | 6 probe | -- | -- | 15 teknik |
| LLM04 Data Poisoning | 7 probe | -- | -- | 15 teknik |
| LLM05 Output Handling | 14 probe | -- | Output rails | 20 teknik + sanitizer |
| LLM06 Excessive Agency | 4 probe | -- | Dialog flow | 20 teknik + tool validator |
| LLM07 Prompt Leakage | divergence | Extraction | Input rails | 25 teknik + canary |
| LLM08 Vector/Embed | -- | -- | -- | 15 teknik |
| LLM09 Misinformation | 7 probe | -- | Fact-check rail | 12 teknik |
| LLM10 Unbounded | -- | -- | Rate limit | 12 teknik |

**En Geniş:** Garak (8/10 OWASP)
**En Derin:** PyRIT (LLM01 multi-turn)
**En Pratik:** NeMo (savunma odaklı)
**En Kapsamlı:** VulnLLM (10/10 OWASP, 194 teknik)

## 4. Performans Karşılaştırması

Test ortamı: Ollama, dolphin-mistral (sansürsüz), llama3.2:3b

| Metrik | Garak | PyRIT | NeMo |
|--------|-------|-------|------|
| Kurulum süresi | ~5 dk | ~10 dk | ~5 dk |
| İlk tarama süresi | ~2-3 saat (smart) | ~5 dk (single-turn) | ~2 dk (8 test) |
| Probe başı süre | ~25-100s | ~10-30s | ~5-15s |
| Bellek kullanımı | Orta | Yüksek (SQLite) | Düşük |
| Timeout riski | Yüksek | Orta | Düşük |

## 5. Entegrasyon ve Kullanılabilirlik

| Özellik | Garak | PyRIT | NeMo |
|---------|-------|-------|------|
| CLI arayüz | Güçlü | Zayıf | Orta |
| Python API | Orta | Güçlü | Güçlü |
| Rapor formatı | JSONL + HTML | SQLite DB | Terminal |
| CI/CD entegrasyonu | Kolay | Orta | Kolay |
| Custom probe/rule | Evet | Evet | Evet (Colang) |
| Ollama desteği | Native | OpenAI-compat | Native |

## 6. Hangi Durumda Hangisini Kullan?

### Garak Kullan:
- Model deployment öncesi kapsamlı zafiyet taraması
- Regresyon testi (yeni model versiyonu çıktığında)
- Compliance check (OWASP LLM Top 10 kapsam raporu)
- Otomatik, tekrarlanabilir tarama gerektiğinde

### PyRIT Kullan:
- Hedefli red team operasyonu
- Multi-turn saldırı senaryoları (Crescendo, TAP)
- Belirli bir zafiyeti derinlemesine test etme
- Saldırı stratejisi geliştirme ve deneme

### NeMo Guardrails Kullan:
- LLM uygulamasına koruma ekleme
- Input/output filtreleme pipeline kurma
- Jailbreak/injection koruması
- Prod ortamında savunma katmanı

### VulnLLM (Kendi Araçlarımız) Kullan:
- Eğitim ve öğrenme amaçlı
- OWASP Top 10 tam kapsam testi
- Kendi saldırı/savunma tekniklerini geliştirme
- Custom guard yazma ve test etme

## 7. Öneriler

1. **Katmanlı yaklaşım:** Garak (geniş tarama) + PyRIT (derin test) + NeMo (savunma)
2. **Pipeline:** Geliştirme -> NeMo koruma -> Garak tarama -> PyRIT red team -> NeMo ince ayar
3. **VulnLLM'i referans olarak kullan:** 194 teknik ve 21 guard kendi baseline'in
4. **Kendi araçlarını entegre et:** LLM Scanner (Garak alternatifi), Firewall (NeMo alternatifi), Detector ML (hızlı pre-check)

## 8. Sonuç

Üç araç birbirini tamamlıyor -- biri diğeri yerine geçmiyor:

```
[Saldırı Genişliği]  Garak ████████████░░ (8/10 OWASP, 181 probe)
[Saldırı Derinliği]  PyRIT ██████████████ (multi-turn, adapte)
[Savunma]            NeMo  ██████████████ (prod-ready rails)
[Eğitim/Kapsam]      VulnLLM ████████████████ (10/10, 194+21)
```

En etkili yaklaşım: üçü birden kullanmak + kendi araçlarını üstüne eklemek.
