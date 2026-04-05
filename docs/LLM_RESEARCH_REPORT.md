# WhiteHatHacker AI — LLM Model Araştırma Raporu

> **Tarih:** 2026-01-15  
> **Donanım:** Mac 64GB Unified Memory + LM Studio  
> **Amaç:** Bug Bounty Hunter Bot için en iyi LLM seçimi  
> **Format Gereksinimi:** GGUF veya MLX, LM Studio uyumlu

---

## 1. MEVCUT MODELLER — KRİTİK ANALİZ

### 1.1 Primary: Trendyol-Cybersecurity-LLM-Qwen3-32B

| Özellik | Değer |
|---------|-------|
| **Base Model** | Qwen/Qwen3-32B |
| **Fine-tune** | Trendyol SFT (cybersecurity) |
| **Parametre** | 32.8B |
| **Quantization** | Q4_K_S (~19GB) |
| **Context** | 16384 (config'de) / 32768 (native) |
| **Downloads** | 214/ay |
| **Likes** | 58 |
| **Benchmark** | ❌ YAYINLANMAMIŞ |

**Tespit Edilen Sorunlar:**

1. **Benchmark yokluğu (KRİTİK):** Model kartı binlerce satır örnek kod ve açıklama içeriyor ama **TEK BİR BENCHMARK SONUCU YOK**. Incident Response, Threat Hunting, Code Analysis, Exploit Development, Reverse Engineering, Malware Analysis başlıkları altında uzun Python kodu örnekleri var — ancak bunlar modelin gerçek çıktısı DEĞİL, aspirasyonel dokümantasyon. Bu büyük bir kırmızı bayrak.

2. **Düşük topluluk benimsemesi:** Vanilla Qwen3-32B'nin 3.5 MİLYON/ay indirmesine karşılık, bu fine-tune sadece 214/ay. Topluluk tarafından ciddi şekilde test edilmemiş.

3. **SFT degradasyonu riski:** Qwen3-32B zaten son derece güçlü bir base model. Sınırlı bir cybersecurity veri setiyle SFT yapmak, modelin **genel reasoning, coding ve agentic yeteneklerini BOZMUŞ OLABİLİR**. Bu, "catastrophic forgetting" olarak bilinen iyi belgelenmiş bir sorundur.

4. **Eğitim verisi kompozisyonu:** %25 vulnerability databases, %20 security advisories, %15 research papers — bunlar genel bilgi içerir. Qwen3-32B'nin pre-training verisi zaten bu kaynakları kapsar. Fine-tune'un eklediği gerçek değer belirsiz.

5. **Context kullanımı:** Config'de 16384 olarak sınırlandırılmış, Qwen3-32B native olarak 32768 destekler.

### 1.2 Secondary: GPT-OSS-Cybersecurity-20B-Merged

| Özellik | Değer |
|---------|-------|
| **Base Model** | openai/gpt-oss-20b |
| **Fine-tune** | LoRA-16, 2 epoch, ~50K sample |
| **Parametre** | 21B total / 3.6B aktif (MoE) |
| **Quantization** | Q4_K_M |
| **Context** | 8192 (config) |
| **Max Training Seq** | ⚠️ **1024 TOKEN** |
| **Downloads** | 93/ay |
| **Likes** | 3 |

**Tespit Edilen Sorunlar:**

1. **1024 token eğitim limiti (FELAKET):** Model sadece 1024 token uzunluğundaki dizilerde eğitilmiş. Bu, karmaşık cybersecurity analizleri, uzun HTTP response'ları, detaylı vulnerability raporları için **tamamen yetersiz**. Context window 8192 olsa bile, model 1024'ün ötesinde tutarsızlaşır.

2. **3.6B aktif parametre (ÇOK ZAYIF):** MoE mimarisinde sadece 3.6B parametre aktif. Bu, bir 4B dense modele eşdeğer reasoning kapasitesi demek — 7B Llama modellerinden bile zayıf.

3. **Solo geliştirici, minimal doğrulama:** 3 like, bir enthusiast projesi. Profesyonel validasyon yok.

4. **Belirsiz base model:** openai/gpt-oss-20b nispeten yeni ve az test edilmiş bir model.

5. **Hafif fine-tune:** LoRA rank 16, sadece 2 epoch — modelin davranışını anlamlı şekilde değiştirecek kadar derin değil.

---

## 2. ARAŞTIRILAN ALTERNATİF MODELLER

### 2.1 Cybersecurity-Specific Modeller

#### A) BaronLLM Offensive Security (AlicanKiraz0)
| Özellik | Değer |
|---------|-------|
| Base | Llama-3.1-8B-Instruct |
| Boyut | 8B, Q6_K = 6.6GB |
| Likes | 141 (en yüksek cybersec GGUF) |
| Downloads | 619/ay |
| Odak | **Offensive** — ATT&CK zincirleri, exploit reasoning, payload refactoring |
| Context | 8192 |

**Değerlendirme:** Ofansif güvenliğe odaklı, bu projemize uygun. Ancak **8B parametre bug bounty'nin gerektirdiği derin reasoning için yetersiz**. Basit XSS/SQLi triage'ı için iyi ama karmaşık business logic, SSRF zincirleme, race condition analizi için zayıf.

#### B) Seneca-Cybersecurity-LLM (AlicanKiraz0)
| Özellik | Değer |
|---------|-------|
| Base | SenecaLLM-x-Llama3.1-8B |
| Boyut | 8B, Q4_K_M = 4.92GB |
| Likes | 33 |
| Downloads | 290/ay |
| Eğitim | ~100 saat (1x4090, 8x4090, 3xH100) |

**Değerlendirme:** Kapsamlı eğitim ama yine 8B sınırı. Yetersiz.

#### C) Trendyol-Cybersecurity-LLM-v2-70B-Q4_K_M ⚠️
| Özellik | Değer |
|---------|-------|
| Base | Llama-3.3-70B-Instruct |
| Boyut | 70B, Q4_K_M = 42.5GB |
| Likes | 36 |
| Downloads | 565/ay |
| CS-Eval | 91.03 ortalama (**3. sıra EN, 5. sıra EN-ZH**) |
| Dataset | 83,920 rows (v2, çok kapsamlı) |

**Değerlendirme:** Gerçek benchmark sonuçları olan TEK ciddi cybersecurity modeli. ANCAK:
- **42.5GB** → 64GB Mac'te tight fit (context + OS overhead ile sorunlu)
- **DEFANSİF odaklı:** "offensive examples were removed; defensive, safe outputs are preferred"
- **Refusal-by-design:** Exploit ve payload oluşturma isteklerini REDDEDER
- Bu, bug bounty hunter bot için **TAM TERSİ**. PoC generate edemez, payload craft edemez.

#### D) Lily-Cybersecurity-7B (segolilylabs)
- 7B model, 29 likes, eski (2024-01)
- Yetersiz boyut, güncel değil

### 2.2 Genel Amaçlı Modeller (GGUF, LM Studio uyumlu)

#### A) Qwen3-32B (Vanilla) ⭐⭐⭐ EN GÜÇLÜ ADAY
| Özellik | Değer |
|---------|-------|
| Parametre | 32.8B (dense) |
| Downloads | **3,511,708/ay** |
| Likes | 665 |
| Context | 32,768 native / 131,072 YaRN |
| Thinking Mode | ✅ /think ve /no_think |
| Tool Calling | ✅ Native (MCP destekli) |
| Multilingual | 119 dil |
| License | Apache 2.0 |
| GGUF Boyutları | Q4_K_M=19.8GB, Q5_K_M=23.2GB, Q6_K=26.9GB, Q8_0=34.8GB |

**Neden #1 Aday:**
1. **Mevcut primary ile AYNI BASE MODEL** — Trendyol fine-tune'u Qwen3-32B üzerine yapılmış. Vanilla versiyon, SFT degradasyonu olmadan tüm orijinal kapasiteyi koruyor
2. **Thinking/Non-thinking modu:** `/think` → derin analiz (primary brain), `/no_think` → hızlı triage (secondary brain). **TEK MODEL İLE İKİ BEYİN ARKİTEKTÜRÜ!**
3. **Native tool calling + MCP:** Bot'un araç orkestrasyon ihtiyacı için mükemmel
4. **32K context native:** Mevcut primary'nin 2x'i, secondary'nin 32x'i
5. **Benchmark kanıtlanmış:** DeepSeek-R1, o1, o3-mini ile yarışıyor
6. **3.5M/ay download:** Devasa topluluk validasyonu
7. **Cybersecurity bilgisi zaten var:** 36T token pre-training verisi CVE'ler, güvenlik araştırmaları, exploit DB'leri, PortSwigger, NVD içeriyor
8. **System prompt ile yönlendirme:** Cybersecurity uzmanlığı prompt engineering ile sağlanabilir — fine-tune gereksiz

#### B) Qwen3-30B-A3B (MoE)
| Özellik | Değer |
|---------|-------|
| Total Params | 30B |
| Active Params | 3B |
| Expert/Aktif | 128 / 8 |
| Context | 32,768 native / 128K YaRN |
| Thinking Mode | ✅ |

**Değerlendirme:** QwQ-32B'yi (10x aktif parametre ile) aşıyor — çok verimli. Ancak 3B aktif parametre, karmaşık güvenlik analizi için sınırlayıcı olabilir. **Secondary brain olarak potansiyel** ama vanilla Qwen3-32B'nin non-thinking modu zaten bu rolü karşılıyor.

#### C) Qwen3-235B-A22B (MoE Flagship)
| Özellik | Değer |
|---------|-------|
| Total Params | 235B |
| Active Params | 22B |
| GGUF Q2_K | 85.7GB |
| GGUF Q4_K_M | 142GB |

**Değerlendirme:** Nihai performans ama **64GB Mac'e sığmaz**. Q2_K bile 86GB. Elenmiştir.

#### D) DeepSeek-R1-Distill-Qwen-32B
| Özellik | Değer |
|---------|-------|
| Base | Qwen2.5-32B |
| Specialization | Reasoning (R1 distillation) |
| Context | 32768 |
| GGUF Q4_K_M | ~19GB |

**Değerlendirme:** Mükemmel reasoning yeteneği. Ancak:
- Her zaman "thinking" modunda (quick mode yok)
- Qwen2.5 base (Qwen3 değil — eski nesil)
- Tool calling / agentic yetenek Qwen3 kadar güçlü değil
- Thinking overhead her sorgu için latency ekler

#### E) Llama 3.3 70B (Meta)
| Özellik | Değer |
|---------|-------|
| Parametre | 70B |
| GGUF Q4_K_M | ~42GB |

**Değerlendirme:** Güçlü model ama 42GB = 64GB Mac'te tight. Qwen3-32B daha iyi performans/boyut dengesi sunuyor.

#### F) Phi-4 (Microsoft) / Gemma 3 27B (Google)
- Phi-4: 14B, iyi reasoning ama küçük
- Gemma 3 27B: İyi ancak Qwen3-32B benchmark'larının gerisinde
- Her ikisi de Qwen3-32B'nin genel üstünlüğüne ulaşamıyor

---

## 3. DONANIM KISITLAMA ANALİZİ (64GB Mac)

```
Kullanılabilir RAM (tahmini):
  64GB Total
  - ~6GB macOS + arka plan
  - ~2GB LM Studio overhead  
  = ~56GB model + context için kullanılabilir

Tek Model Yükleme:
  Qwen3-32B Q8_0:   34.8GB ✅ (21GB kalan — context için iyi)
  Qwen3-32B Q6_K:   26.9GB ✅ (29GB kalan — geniş context)
  Qwen3-32B Q5_K_M: 23.2GB ✅ (33GB kalan — ideal denge)
  Qwen3-32B Q4_K_M: 19.8GB ✅ (36GB kalan — bol context)

Çift Model Yükleme (Simultaneous):
  Qwen3-32B Q4_K_M (19.8GB) + Qwen3-8B Q6_K (6.6GB) = 26.4GB ✅
  Qwen3-32B Q4_K_M (19.8GB) + Qwen3-14B Q4_K_M (~9GB) = 28.8GB ✅
  Qwen3-32B Q5_K_M (23.2GB) + Qwen3-8B Q4_K_M (~5GB) = 28.2GB ✅
```

---

## 4. ÖNERİLER (Öncelik Sırasına Göre)

### 🏆 ÖNERİ #1: TEK MODEL — Qwen3-32B Vanilla (Q6_K)

```
Model: unsloth/Qwen3-32B-GGUF (Q6_K quantization)
Boyut: 26.9GB
Kalan RAM: ~29GB (context + inference için mükemmel)
```

**Neden bu en iyi seçim:**

| Kriter | Mevcut Primary | Mevcut Secondary | Önerilen Qwen3-32B |
|--------|---------------|-----------------|---------------------|
| Reasoning | İyi (ama SFT bozmuş olabilir) | Zayıf (3.6B aktif) | **Üstün** (native Qwen3) |
| Context | 16384 | 1024 (training limit!) | **32,768** (native) |
| Tool Calling | Yok (native) | Yok | **✅ Native MCP** |
| Thinking Mode | Yok | Yok | **✅ /think + /no_think** |
| Coding | İyi | Zayıf | **Üstün** |
| Downloads | 214/ay | 93/ay | **3,511,708/ay** |
| Benchmark | ❌ Yok | ❌ Yok | **✅ DeepSeek-R1 seviyesi** |
| Cybersec Bilgi | SFT ile ek | SFT ile ek | Pre-train'de mevcut + prompt ile |

**Dual-Brain Nasıl Çalışır (Tek Model İle):**
- **Primary Brain görevleri:** `temperature=0.6, /think` → Model düşünüp detaylı analiz yapar
- **Secondary Brain görevleri:** `temperature=0.7, /no_think` → Hızlı, direkt yanıt
- **Ensemble:** Aynı model'e iki farklı modda sorulur, sonuçlar karşılaştırılır
- **Bonus:** Model swap latency = 0 (tek model yüklü)

### 🥈 ÖNERİ #2: ÇİFT MODEL — Qwen3-32B + Qwen3-8B

```
Primary:   Qwen3-32B Q4_K_M (19.8GB) — Thinking mode, derin analiz
Secondary: Qwen3-8B  Q6_K   (6.6GB)  — Non-thinking, hızlı triage
Toplam:    26.4GB (ikisi aynı anda yüklü kalabilir)
```

**Avantaj:** İki model aynı anda bellekte → sıfır swap süresi, gerçek paralel çalışma.  
**Dezavantaj:** Secondary (8B) Qwen3-32B non-thinking modundan biraz daha zayıf.

### 🥉 ÖNERİ #3: TEK MODEL — Qwen3-32B Vanilla (Q8_0 / Maksimum Kalite)

```
Model: unsloth/Qwen3-32B-GGUF (Q8_0 quantization)
Boyut: 34.8GB
Kalan RAM: ~21GB
```

**Avantaj:** En yüksek kaliteli quantization, Q6_K'dan daha doğru.  
**Dezavantaj:** Context için daha az RAM kalıyor. Uzun analizlerde memory pressure olabilir.

---

## 5. ÖNERİ #1 İÇİN İMPLEMENTASYON PLANI

### 5.1 LM Studio'da Model Yükleme
1. LM Studio'da `unsloth/Qwen3-32B-GGUF` araması yap
2. **Q6_K** (26.9GB) sürümünü indir (veya Q5_K_M=23.2GB eğer daha fazla context istenirse)
3. Model'i LM Studio'da yükle
4. GPU Offload: Maksimum (Mac Metal'e tam offload)
5. Context Length: 32768

### 5.2 Config Değişiklikleri

**settings.yaml** değişiklikleri:
```yaml
brain:
  primary:
    name: Qwen3-32B
    backend: remote
    api_url: ${WHAI_PRIMARY_API_URL:-http://127.0.0.1:1239}
    api_key: ${WHAI_PRIMARY_API_KEY:-}
    model_name: qwen3-32b-q6_k          # LM Studio'daki model adı
    context_length: 32768                 # 16384 → 32768 (2x artış!)
    temperature: 0.6                      # Thinking mode default
    top_p: 0.95
    top_k: 20
    repeat_penalty: 1.1
    max_tokens: 8192                      # 4096 → 8192 (daha uzun analiz)
    timeout: 600.0
  secondary:
    name: Qwen3-32B-Fast
    backend: remote
    api_url: ${WHAI_SECONDARY_API_URL:-http://127.0.0.1:1239}
    api_key: ${WHAI_SECONDARY_API_KEY:-}
    model_name: qwen3-32b-q6_k          # AYNI MODEL
    context_length: 32768
    temperature: 0.7                      # Non-thinking mode
    top_p: 0.8
    top_k: 20
    repeat_penalty: 1.05
    max_tokens: 2048
    timeout: 120.0
```

### 5.3 Brain Engine Prompt Değişiklikleri

Primary brain çağrılarında thinking mode aktifleştirme:
```
System: "You are an expert bug bounty hunter... /think"
```

Secondary brain çağrılarında hızlı mod:
```
System: "You are a cybersecurity assistant... /no_think"
```

### 5.4 Yeni Özellik: Native Tool Calling

Qwen3-32B'nin native tool calling desteği sayesinde, brain engine'e function calling API desteği eklenebilir. Bu, araç seçimi ve parametre belirleme görevlerini dramatik şekilde iyileştirecektir.

---

## 6. KARŞILAŞTIRMA TABLOSU

| Model | Parametre | GGUF Boyut | Context | Benchmark | Tool Call | Think/NoThink | Cybersec | Download | Uygunluk |
|-------|-----------|-----------|---------|-----------|-----------|---------------|----------|----------|----------|
| **Qwen3-32B (vanilla)** | **32.8B** | **Q6_K=26.9GB** | **32,768** | **✅ Top-tier** | **✅ Native** | **✅** | **Pre-train** | **3.5M/ay** | **⭐⭐⭐⭐⭐** |
| Trendyol-Qwen3-32B (mevcut) | 32.8B | Q4_K_S=19GB | 16,384 | ❌ Yok | ❌ | ❌ | SFT | 214/ay | ⭐⭐ |
| GPT-OSS-20B (mevcut) | 3.6B aktif | Q4_K_M=16GB | 1,024* | ❌ Yok | ❌ | ❌ | SFT | 93/ay | ⭐ |
| Trendyol-v2-70B | 70B | Q4_K_M=42.5GB | 128K | ✅ CS-Eval 91 | ❌ | ❌ | SFT (DEF) | 565/ay | ⭐⭐ (RAM!) |
| BaronLLM | 8B | Q6_K=6.6GB | 8,192 | ❌ Yok | ❌ | ❌ | SFT (OFF) | 619/ay | ⭐⭐ (küçük) |
| DeepSeek-R1-Distill-32B | 32B | Q4_K_M=19GB | 32,768 | ✅ | ❌ | ❌ (hep think) | Pre-train | 1.2M/ay | ⭐⭐⭐ |
| Qwen3-30B-A3B (MoE) | 3B aktif | ~18GB | 32,768 | ✅ | ✅ | ✅ | Pre-train | 500K/ay | ⭐⭐⭐ |

*GPT-OSS-20B: Config'de 8192 ama training limit 1024*

---

## 7. QWEN3.5 ANALİZİ — NEDEN QWEN3, QWEN3.5 DEĞİL?

> **Araştırma Tarihi:** 2026-03-03 (Qwen3.5 birkaç gün önce yayınlandı)
> **Durum:** Qwen3.5 var ve çok yeni — ama bizim projemiz için ciddi engelleri var.

### 7.1 Qwen3.5 Nedir?

Qwen3.5, Qwen Team'in Şubat 2026'da yayınladığı **yeni nesil multimodal** (Vision+Language) model ailesidir.
Slogan: *"Towards Native Multimodal Agents"*

| Model | Parametre | Mimari | GGUF Boyut (Q4_K_M) | İndirme/ay |
|-------|-----------|--------|---------------------|------------|
| Qwen3.5-397B-A17B | 403B MoE (17B aktif) | MoE + DeltaNet | ❌ 64GB'a sığmaz | 1.25M |
| Qwen3.5-122B-A10B | 125B MoE (10B aktif) | MoE + DeltaNet | ❌ 64GB'a sığmaz | 150K |
| **Qwen3.5-35B-A3B** | **36B MoE (3B aktif)** | **MoE + DeltaNet** | **~19.9GB** | **680K** |
| **Qwen3.5-27B** | **28B dense** | **Dense + DeltaNet** | **~16-17GB (tahmini)** | **319K** |

### 7.2 Benchmark Karşılaştırma (Language/Text-Only)

Qwen3.5 modellerinin text benchmark'ları **etkileyici**:

| Benchmark | Qwen3.5-27B | Qwen3.5-35B-A3B | Qwen3-32B (vanilla) |
|-----------|-------------|-----------------|---------------------|
| MMLU-Pro | **86.1** | 85.3 | ~79.8 |
| GPQA Diamond | **85.5** | 84.2 | 72.4 |
| SWE-bench Verified | **72.4** | 69.2 | 49.0 |
| LiveCodeBench v6 | **80.7** | 74.6 | 70.6 |
| IFEval | **95.0** | 91.9 | 86.4 |
| CodeForces | 1899 | 2028 | ~1700 |
| BFCL-V4 (Tool Call) | **68.5** | 67.3 | ~55 |
| TerminalBench 2 | **41.6** | 40.5 | ~18 |
| TAU2-Bench (Agent) | **79.0** | 81.2 | ~58 |

**Sonuç:** Qwen3.5-27B, Qwen3-32B'den benchmark'larda **açık ara üstün**. Özellikle coding (SWE-bench %47 fark!), agentic (TAU2 %36 fark!) ve tool calling (BFCL %25 fark!) alanlarında.

### 7.3 ANCAK — 5 Kritik Engel

#### ENGEL 1: `/think` ve `/nothink` DESTEKLENMIYOR ❌ (DEAL-BREAKER)

Qwen3.5 model kartından doğrudan alıntı:

> *"Qwen3.5 does not officially support the soft switch of Qwen3, i.e., `/think` and `/nothink`."*

Bizim **tüm dual-brain planımız** Qwen3'ün `/think` (primary) ve `/no_think` (secondary) soft-switch'ine dayanıyor. Qwen3.5'te bu yok. Thinking modu kapatmak için sunucu seviyesinde `enable_thinking: False` API parametresi gerekiyor — bu LM Studio'da nasıl çalışacağı belirsiz.

**Etki:** Dual-brain mimarimiz için temel olan think/nothink modunu **mesaj içinde kontrol edemeyiz**.

#### ENGEL 2: Multimodal Overhead — Vision Encoder Gereksiz ❌

Qwen3.5'in tüm modelleri "Causal Language Model **with Vision Encoder**" olarak tanımlı. Bu:
- GGUF'a çevrildiğinde vision encoder ağırlıkları dahil → **ek bellek tüketimi**
- Text-only kullanımda bu ağırlıklar **boşa yer kaplar**
- vLLM `--language-model-only` flag'i ile skip edilebilir ama LM Studio / llama.cpp'de böyle bir opsiyon **yok**
- Aynı parametre sayısında, text-only model daha verimli çalışır

#### ENGEL 3: LM Studio Uyumluluğu BELİRSİZ ⚠️

Qwen3.5 **tamamen yeni bir mimari** kullanıyor:
- **Gated DeltaNet** (linear attention varyantı) — standart transformer attention DEĞİL
- Architecture ID: `qwen3_5` (dense) ve `qwen3_5_moe` (MoE)
- Bu mimari llama.cpp'de ve LM Studio'da henüz **stabil şekilde desteklenmiyOR olabilir**
- GGUF'lar unsloth tarafından sağlanıyor ama "Feb 27 Update: GGUFs Refreshed + Tool-calling fixes" notu var → hâlâ düzeltmeler yapılıyor
- Resmi serving: SGLang, vLLM, KTransformers — bunlar GPU sunucu framework'leri, **Mac/LM Studio değil**

**Risk:** LM Studio'da modeli yükleyip çalışamama, crash veya sessiz kalite düşüşü riski var.

#### ENGEL 4: Qwen3.5-35B-A3B'nin 3B Aktif Parametresi ❌

Qwen3.5-35B-A3B: 256 expert, sadece **8 routed + 1 shared = 3B aktif**. Bu, mevcut GPT-OSS secondary modelimizdeki **aynı problem**: düşük aktif parametre = sınırlı reasoning.

Qwen3.5-27B ise 28B dense — daha iyi, ama Qwen3-32B'nin (32.8B dense) parametresinden **%15 daha az**.

#### ENGEL 5: Çok Yeni = Stabil Değil ⚠️

- Yayınlanma: Şubat 2026 (birkaç gün önce!)
- GPTQ versiyonları **saatler önce** yayınlanıyordu
- GGUF'lar "refreshed + fixes" ile güncelleniyor
- Community issues: 26-40 açık tartışma (Qwen3'te çok daha az)
- Bu kadar yeni bir model **production-ready değil**

### 7.4 Karar Matrisi: Qwen3-32B vs Qwen3.5

| Kriter | Qwen3-32B | Qwen3.5-27B | Qwen3.5-35B-A3B | Kazanan |
|--------|-----------|-------------|-----------------|---------|
| Text Benchmarks | İyi | **Çok iyi** | İyi | Qwen3.5-27B |
| `/think` `/nothink` | **✅ Native** | ❌ Yok | ❌ Yok | **Qwen3-32B** |
| LM Studio uyumluluk | **✅ Stabil** | ⚠️ Belirsiz | ⚠️ Belirsiz | **Qwen3-32B** |
| Multimodal overhead | **Yok** | ~2-3GB ekstra | ~2-3GB ekstra | **Qwen3-32B** |
| Dense parametre | **32.8B** | 28B | 3B aktif | **Qwen3-32B** |
| Stabilite | **✅ Mature** | ⚠️ Günler önce | ⚠️ Günler önce | **Qwen3-32B** |
| Tool calling | ✅ Native | ✅ Native | ✅ Native | Eşit |
| Context | 32K (131K YaRN) | **262K** (1M YaRN) | **262K** (1M YaRN) | Qwen3.5 |
| Download/trust | **3.5M/ay** | 319K/ay | 680K/ay | **Qwen3-32B** |
| Mimari riski | Yok (std transformer) | **Yeni (DeltaNet)** | **Yeni (DeltaNet)** | **Qwen3-32B** |

**Skor: Qwen3-32B 7/10, Qwen3.5-27B 2/10, Qwen3.5-35B-A3B 1/10**

### 7.5 Gelecek Planı: Qwen3.5'e Geçiş Ne Zaman?

Qwen3.5'e geçiş **şu koşullar sağlandığında** değerlendirilmeli:
1. LM Studio / llama.cpp'de Gated DeltaNet mimarisi **stabil** olarak desteklendiğinde
2. `/think` `/nothink` soft-switch veya LM Studio'da `enable_thinking` parametresi desteklendiğinde
3. Topluluk tarafından yeterince test edilip (en az 1M+ download/ay) stabilize olduğunda
4. Text-only GGUF (vision encoder olmadan) versiyonları yayınlandığında

**Tahmini zaman: 2-3 ay sonra değerlendirme yapılmalı.**

---

## 8. SONUÇ

### Kesin Bulgular:

1. **Mevcut secondary model (GPT-OSS-20B) bir felaket.** 1024 token training limiti, 3.6B aktif parametre, 3 like — acil değiştirilmeli.

2. **Mevcut primary model (Trendyol Qwen3-32B) gereksiz.** Vanilla Qwen3-32B ile aynı veya daha iyi performans elde edilir, çünkü SFT degradasyonu riski ortadan kalkar ve native thinking/tool-calling yetenekleri korunur.

3. **Qwen3-32B vanilla, tek başına her iki modeli de replace eder** — thinking mode ile primary, non-thinking mode ile secondary rolünü üstlenir.

4. **64GB Mac için Q6_K (26.9GB) optimal quantization'dır** — quality ve RAM dengesi en iyi bu seviyede.

5. **Cybersecurity domain knowledge, system prompt engineering ile sağlanmalıdır** — LLM fine-tune değil, prompt engineering ile. Bu, modelin genel yeteneklerini korur ve domain bilgisini kolayca güncellenebilir yapar.

6. **Qwen3.5 benchmark'larda Qwen3'ü geçiyor ANCAK şu an kullanılamaz** — `/think`/`/nothink` desteği yok, multimodal overhead var, LM Studio uyumluluğu belirsiz, çok yeni/stabil değil. 2-3 ay sonra yeniden değerlendirilmeli.

### Aksiyon:
> **Qwen3-32B vanilla (Q6_K GGUF) indirip tek model olarak kullanın. Dual-brain mimarisini thinking/non-thinking mode üzerinden sürdürün.**
> **Qwen3.5, stabil olduğunda ve LM Studio desteği geldiğinde yeniden değerlendirilecektir.**
