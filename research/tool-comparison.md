# AI/LLM Guvenlik Araci Karsilastirma Raporu
# Garak vs PyRIT vs NeMo Guardrails

**Tarih:** 2026-05-02
**Ortam:** Windows 11, Ollama (dolphin-mistral, qwen2.5:3b, llama3.2:3b)

---

## 1. Genel Bakis

| Ozellik | Garak (NVIDIA) | PyRIT (Microsoft) | NeMo Guardrails (NVIDIA) |
|---------|----------------|--------------------|-----------------------------|
| **Amac** | Otomatik zafiyet tarama | Red team otomasyon | Programlanabilir koruma |
| **Yaklasim** | Offensive (saldiri) | Offensive (saldiri) | Defensive (savunma) |
| **Versiyon** | v0.14.1 | v0.13.0 | v0.21.0 |
| **Lisans** | Apache 2.0 | MIT | Apache 2.0 |
| **Dil** | Python | Python | Python + Colang DSL |
| **LLM Destegi** | Ollama, OpenAI, HF | OpenAI-compat | Ollama, OpenAI, HF |
| **Kurulum** | `pip install garak` | `pip install pyrit` | `pip install nemoguardrails` |

## 2. Kapsam Karsilastirmasi

### Garak -- Genis Otomatik Tarama
- **37 kategori, 181+ probe** (aktif)
- Her probe yuzlerce permutasyon uretir (256 varsayilan)
- OWASP LLM Top 10'un ~8/10'unu kapsar
- Tek komutla tam model tarama
- Sonuc: JSONL rapor + HTML ozet

**Gucleri:**
- En genis kapsam -- encoding, dan, promptinject, leakreplay, packagehallucination...
- Otomatik ve tekrarlanabilir
- Tier bazli model karsilastirmasi

**Zayifliklari:**
- Cok yavas -- full scan saatler/gunler surebilir
- Probe basi 256 permutasyon genellikle gereksiz fazla
- Basari tespiti (detector) bazen yaniltici
- Ollama ile timeout sorunlari (yavaş modeller)

### PyRIT -- Stratejik Red Team
- **5 saldiri stratejisi:** Single-turn, Crescendo, TAP, PAIR, XPIA
- Multi-turn escalation destegi
- Saldiri hafizasi (SQLite)
- Programatik saldiri zincirleri

**Gucleri:**
- Multi-turn saldirilar (Crescendo, TAP) -- Garak'ta yok
- Saldiri sonuclarini hafizada tutar ve analiz eder
- Daha "akilli" saldiri -- hedefli, adapte olan
- Microsoft'un kendi red team deneyiminden turetilmis

**Zayifliklari:**
- Kucuk modeller JSON format sorunu (rationale_behind_jailbreak key eksik)
- Ollama entegrasyonu OpenAI-compat uzerinden, bazen uyumsuz
- Daha az probe cesidi -- stratejik derinlik var ama genislik yok
- Dokumantasyon karmasik

### NeMo Guardrails -- Programlanabilir Savunma
- **Colang DSL** ile dialog akis tanimlama
- Input/output rail'leri
- Self-check mekanizmasi (LLM-based)
- Jailbreak detection rail

**Gucleri:**
- Savunma tarafi -- diger ikisi saldiri odakli
- Colang DSL ile okunabilir kural tanimlama
- Modular rail sistemi -- istedigin korumayı ekle/cikar
- Prod-ready -- gercek uygulamalara entegre edilebilir

**Zayifliklari:**
- Her prompt icin 3 LLM cagrisi (input check + response + output check) -- yavas
- Ollama ile performans sorunu (kucuk modeller)
- Self-check sadece LLM kadar iyi -- kucuk modeller zayif
- Colang v1 vs v2 geciş sureci

## 3. OWASP LLM Top 10 Kapsami

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

**En Genis:** Garak (8/10 OWASP)
**En Derin:** PyRIT (LLM01 multi-turn)
**En Pratik:** NeMo (savunma odakli)
**En Kapsamli:** VulnLLM (10/10 OWASP, 194 teknik)

## 4. Performans Karsilastirmasi

Test ortami: Ollama, dolphin-mistral (sansursuz), llama3.2:3b

| Metrik | Garak | PyRIT | NeMo |
|--------|-------|-------|------|
| Kurulum suresi | ~5 dk | ~10 dk | ~5 dk |
| Ilk tarama suresi | ~2-3 saat (smart) | ~5 dk (single-turn) | ~2 dk (8 test) |
| Probe basi sure | ~25-100s | ~10-30s | ~5-15s |
| Bellek kullanimi | Orta | Yuksek (SQLite) | Dusuk |
| Timeout riski | Yuksek | Orta | Dusuk |

## 5. Entegrasyon ve Kullanilabilirlik

| Ozellik | Garak | PyRIT | NeMo |
|---------|-------|-------|------|
| CLI arayuz | Guclu | Zayif | Orta |
| Python API | Orta | Guclu | Guclu |
| Rapor formati | JSONL + HTML | SQLite DB | Terminal |
| CI/CD entegrasyonu | Kolay | Orta | Kolay |
| Custom probe/rule | Evet | Evet | Evet (Colang) |
| Ollama destegi | Native | OpenAI-compat | Native |

## 6. Hangi Durumda Hangisini Kullan?

### Garak Kullan:
- Model deployment oncesi kapsamli zafiyet taramasi
- Regresyon testi (yeni model versiyonu ciktiginda)
- Compliance check (OWASP LLM Top 10 kapsam raporu)
- Otomatik, tekrarlanabilir tarama gerektiginde

### PyRIT Kullan:
- Hedefli red team operasyonu
- Multi-turn saldiri senaryolari (Crescendo, TAP)
- Belirli bir zafiyeti derinlemesine test etme
- Saldiri stratejisi gelistirme ve deneme

### NeMo Guardrails Kullan:
- LLM uygulamasina koruma ekleme
- Input/output filtreleme pipeline kurma
- Jailbreak/injection koruması
- Prod ortaminda savunma katmani

### VulnLLM (Kendi Araclarimiz) Kullan:
- Egitim ve ogrenme amacli
- OWASP Top 10 tam kapsam testi
- Kendi saldiri/savunma tekniklerini gelistirme
- Custom guard yazma ve test etme

## 7. Oneriler

1. **Katmanli yaklasim:** Garak (genis tarama) + PyRIT (derin test) + NeMo (savunma)
2. **Pipeline:** Gelistirme -> NeMo koruma -> Garak tarama -> PyRIT red team -> NeMo ince ayar
3. **VulnLLM'i referans olarak kullan:** 194 teknik ve 21 guard kendi baseline'in
4. **Kendi araclarini entegre et:** LLM Scanner (Garak alternatifi), Firewall (NeMo alternatifi), Detector ML (hizli pre-check)

## 8. Sonuc

Uc arac birbirini tamamliyor -- biri digeri yerine gecmiyor:

```
[Saldiri Genisligi]  Garak ████████████░░ (8/10 OWASP, 181 probe)
[Saldiri Derinligi]  PyRIT ██████████████ (multi-turn, adapte)
[Savunma]            NeMo  ██████████████ (prod-ready rails)
[Egitim/Kapsam]      VulnLLM ████████████████ (10/10, 194+21)
```

En etkili yaklasim: ucu birden kullanmak + kendi araclarini ustune eklemek.
