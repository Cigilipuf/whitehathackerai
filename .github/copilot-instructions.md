# WhiteHatHacker AI - Bug Bounty Hunter Bot :: Copilot Instructions

> **Proje:** WhiteHatHacker AI — Otonom Bug Bounty Hunter Bot
> **Versiyon:** 3.5
> **Tarih:** 2026-03-17
> **Mantık Modeli:** Hibrit (Tam Otonom / Yarı Otonom geçişli)
> **Paradigma:** Scanner → HUNTER → AGENTIC dönüşümü tamamlandı (ReAct Agent Loop + HUNTER MODE + PROOF-OF-EXPLOIT aktif)

---

## 🧠 PROJE KİMLİĞİ VE MİSYONU

Bu proje, iki adet fine-tune edilmiş siber güvenlik LLM modelini "beyin" olarak kullanan, profesyonel bir bug bounty hunter gibi çalışan otonom bir siber güvenlik botudur. Bot, Kali Linux ve ötesindeki tüm güvenlik araçlarını orkestra ederek hedef sistemlerdeki gerçek güvenlik açıklarını tespit eder, doğrular ve profesyonel raporlar üretir.

### Temel Aksiyomlar (Geliştirme Felsefesi)

Bu projenin geliştirilmesinde üç temel aksiyom geçerlidir:

**AKSİYOM 1 — YETERSİZLİK:** Bir programda zafiyet BULAMAMAMIZ, orada zafiyet OLMADIĞI anlamına GELMEZ. Geliştirmenin sınırı yoktur. "Yeterli" diye bir kavram yoktur. Her template, her exploit, her teknik sadece başlangıç noktasıdır — gerçek ihtiyaç bunların 100x, 1000x genişletilmiş versiyonlarıdır.

**AKSİYOM 2 — BUZDAĞI:** Bu dokümantasyondaki ve koddaki her şey, yapılması gerekenin çok küçük bir kısmını ifade eder. Her örnek SADECE bir örnektir, tamamlanacaklar listesi DEĞİLDİR. 25 XSS payload varsa, gerçekte 25.000+ payload olmalıdır. Her zafiyet türü × her teknoloji × her context = yeni test, yeni template gerektirir.

**AKSİYOM 3 — İNTERNET ERİŞİMİ:** Bu bot gerçek dünyada çalışan bir güvenlik araştırma sistemidir. Gerçek hedeflere gerçek HTTP istekleri gönderir, gerçek response'ları analiz eder, gerçek exploit'leri test eder. LLM'ler internete erişerek yeni CVE'leri araştırır, yeni teknikler öğrenir, güncel WAF davranışlarını analiz eder.

**Aksiyomların Sinerji Etkisi:**
- AKSİYOM 1 + 2: "Bu dosyadaki örnekleri yaptım" = "HENÜZ BAŞLADIM"
- AKSİYOM 1 + 3: LLM internete erişerek gerçek hedefleri test etmeli, sonuçlardan öğrenerek sonsuz döngüde kendini geliştirmelidir
- AKSİYOM 2 + 3: Sınırlı örnekler internete erişim sayesinde sınırsız gerçek dünya bilgisiyle zenginleştirilmelidir

### HUNTER MODE Mimarisi (v2.2 — Aktif)

Bot artık bir "scanner" DEĞİL, bir "hunter"dır. Temel fark: Scanner araç çalıştırıp sonuç okur. Hunter ise LLM'i aktif olarak keşif, hipotez üretme, payload tasarlama, response analizi ve iteratif derinleşme için kullanır.

```
HUNTER MODE (3 Faz):
├── Phase A: Custom Nuclei Template Generation (LLM → YAML)
│   ├── Brain attack vectors → endpoint-specific templates
│   ├── Technology-aware payload selection
│   └── Auto-validation + LLM retry on YAML errors
├── Phase B: Deep Probe (Iterative LLM-Driven Testing)
│   ├── ANALYZE → HYPOTHESIZE → PROBE → OBSERVE → ADAPT → LOOP
│   ├── Auth token injection for authenticated endpoints
│   ├── Multi-iteration hypothesis refinement
│   └── Confidence-based escalation to PoC
└── Phase C: PoC Execution & Evidence Collection
    ├── ExploitVerifier — 4 strategies (PoC/Metasploit/curl/Nuclei)
    ├── Metasploit tech-aux + CVE auto-exploit (pre-Phase C)
    ├── EvidenceAggregator — unified package per finding
    ├── Cryptographic evidence chain with integrity hash
    └── No finding limit — all qualifying findings verified
```

**Kanıtlanmış Performans (Scan 12, Vimeo.com):**
| Metrik | Scan 11 (pre-HUNTER) | Scan 12 (HUNTER) |
|--------|---------------------|-------------------|
| PoC Confirmed | 1/8 (12.5%) | 7/8 (87.5%) |
| PoC Gen Time | 120s timeout | < 15s template |
| False HIGH | 2 (ANSI artifact) | 0 |
| Templates Generated | 1 (2 failed) | 4+ success |
| Deep Probe | SKIPPED | ACTIVATED |

### Beyin Modelleri (Dual-Brain Architecture)

| Model | Dosya | Parametre | Kullanım |
|-------|-------|-----------|----------|
| **Primary Brain** | `AlicanKiraz0/BaronLLM-v2-OffensiveSecurity-GGUF` (Q8_0) | 15B (Qwen3-14B base) | Derin analiz, exploit stratejisi, false positive eleme, rapor yazma, stratejik planlama |
| **Secondary Brain** | Aynı model, `/no_think` mode | 15B (/no_think) | Hızlı triage, recon kararları, tool seçimi, paralel analiz (CoT devre dışı) |
| **Fallback Brain** | `Neanderthal/DeepHat-V1-7B-GGUF` (Q4_K_M) | 7.61B (Qwen2.5-Coder-7B base) | Acil durum fallback — sadece primary+secondary her ikisi de down olduğunda |

Her iki ana model de GGUF formatındadır (BaronLLM v2, Q8_0, 15.7GB). Dual-backend destegi sayesinde **LOCAL** (`llama-cpp-python`) veya **REMOTE** (LM Studio / OpenAI-uyumlu API, `httpx` SSE streaming) üzerinden çalıştırılabilir. Backend seçimi `config/settings.yaml` → `brain.primary.backend` / `brain.secondary.backend` ile yapılır (`local` | `remote`). Model seçimi görev karmaşıklığına göre otomatik yapılır veya manuel override edilebilir. Tek model dual-brain olarak çalıştığından (15.7GB), Mac'in 64GB unified memory'sinde ~48GB boş kalır — daha geniş context window ve daha hızlı inference mümkündür.

### LLM Entegrasyon Güçlendirmeleri (v2.2)

Session 6'da gerçekleştirilen derin LLM entegrasyon iyileştirmeleri:

**Brain Response Cache (E1):** `IntelligenceEngine._cache` — Hash tabanlı response cache. Aynı prompt tekrar sorulursa LLM çağrısı atlanır, ~10-60s kazanç. Max 200 entry, FIFO eviction.

**Central Brain-Down Flag (B2):** `IntelligenceEngine._brain_down` — 3 ardışık başarısızlıktan sonra brain "down" olarak işaretlenir ve tüm sonraki çağrılar anında atlanır. Gereksiz timeout bekleme sürelerini elimine eder.

**Asymmetric Confidence Merging (D4):** Brain confidence merge artık asimetrik: brain bulguyu yükseltiyorsa 60/40 (brain/detector), düşürüyorsa 30/70, yani araç kanıtı korunur.

**Payload Safety Filter (D2):** `_UNSAFE_PAYLOAD_RE` — LLM'in ürettiği payload'larda `rm -rf`, `DROP TABLE`, `shutdown` gibi yıkıcı komutları otomatik engelleyen regex filtresi.

**Scope-Validated Brain Endpoints (D1):** Brain'in önerdiği `high_value_endpoints` artık scope validator'dan geçirilir, hallüsinasyon kaynaklı out-of-scope URL'ler filtrelenir.

**English FP Prompts with Few-Shot Examples (C1+C4):** Tüm FP analiz prompt'ları Türkçe'den İngilizce'ye çevrildi (Qwen3 İngilizce'de daha iyi performans gösterir). 3 kalibrasyon örneği (true positive, false positive, WAF artifact) eklendi.

**Token Efficiency (C6+F2):** `analyze_recon_and_plan()` artık URL'leri path pattern'a göre deduplicate eder, sıkıcı subdomain'leri filtreler. Prompt token tahmini yapılarak context window aşımı uyarısı verilir.

**Shared JSON Extractor (T0-1):** `src/utils/json_utils.py` — Tüm LLM response parsing'i tek noktadan yapılır. Markdown fence'ler, brace counting, trailing comma, single quote gibi edge case'leri handle eder. `intelligence.py`, `fp_detector.py`, `full_scan.py` ve `payload_generator.py` entegre edildi.

**Brain CoT Logging (D3):** Qwen3'ün `<think>` bloğu artık debug log'a yazılır, model reasoning'i izlenebilir.

### v2.3 Güçlendirmeleri (NEXT_LEVEL_PLAN_V6)

Session 9'da gerçekleştirilen v2.3 iyileştirmeleri:

**LLM Pre-Hoc Strategist (V6-T0-2):** `IntelligenceEngine.generate_creative_attack_narratives()` — Scan başlamadan ÖNCE LLM'den yaratıcı saldırı senaryoları ister. Teknoloji stack'e göre hipotez üretir, business logic açıkları öngörür.

**Dynamic Test Case Generation (V6-T0-4):** `IntelligenceEngine.generate_dynamic_test_cases()` — Her endpoint için teknoloji-spesifik dinamik test case'leri LLM ile üretir. Template tabanlı statik testlerin ötesine geçer.

**Cross-Finding LLM Reasoning (V6-T0-3):** `CorrelationEngine.detect_chains_llm()` — Kural tabanlı 9 KNOWN_CHAINS'in ötesinde, LLM ile tüm bulguları analiz ederek yeni saldırı zincirleri keşfeder. Rule-based + LLM hibrit korelasyon.

**WAF Fingerprint & Adaptive Strategy (V6-T2-1):** `src/tools/scanners/waf_strategy.py` — Response header/cookie/body analizi + wafw00f ile WAF tespiti. 8 WAF profili (Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5 BIG-IP, Sucuri, Wordfence) için encoding chain, rate adjustment, header tweak, payload transform stratejileri. Nuclei rate otomatik WAF'a göre ayarlanır.

**JWT Deep Security Checker (V6-T4-1):** `src/tools/scanners/custom_checks/jwt_checker.py` — 7 test: alg:none bypass (4 varyant), weak HMAC secret brute-force (18 common secret), expired token acceptance, kid header injection (3 path traversal), signature stripping, claim tampering (role/admin elevation).

**Re-request FP Verification Layer (V6-T4-2):** `FPDetector._layer6_rerequest_verify()` — MEDIUM+ severity bulgular için: orijinal isteği tekrar gönderir, query parametresiz kontrol isteği gönderir, status code + body length karşılaştırması yapar. Reproduced → +10, not reproduced → -8.

**Payload Arsenal Expansion (V6-T3-1/2/3/4):** XSS 513→759 (mXSS, DOMPurify bypass, CSP bypass, WAF evasion, SVG/MathML, polyglots, blind XSS), SQLi 462→426 (deduplicated + second-order, JSON/GraphQL, OOB), SSRF 394→325 (deduplicated + K8s/Docker, cloud metadata, DNS rebinding). 4 yeni kategori: jwt.txt (25), deserialization.txt (19), prototype_pollution.txt (21), graphql.txt (19). Toplam: 14 dosya, 3,669 payload.

### v2.4 Güçlendirmeleri (NEXT_LEVEL_PLAN_V7)

Session 11'de gerçekleştirilen v2.4 iyileştirmeleri (21 modül, 5 tier):

**Tier 0 — Core Infrastructure:**

**Scan Benchmarking Framework (V7-T0-1):** `src/analysis/benchmark.py` — `ScanBenchmark` dataclass (scan_id, target, duration, endpoints_tested, tools_run, raw/confirmed findings, fp_rate, severity breakdown, PoC success rate, brain metrics). `BenchmarkStore` SQLite persistence. `BenchmarkDiff` iki scan karşılaştırması.

**Asset Database (V7-T0-2):** `src/integrations/asset_db.py` — `AssetDB` SQLite tabanlı her scope için persistent varlık takibi. `Asset` model (type, value, first_seen, last_seen, is_alive). `upsert_assets()`, `diff_assets()` (AssetDiff: new/disappeared/changed), `save_finding()`, `record_scan_start/finish()`, `get_scan_runs()`, `get_findings()`.

**Pipeline Integration Hooks (V7-T0-3):** `src/workflow/pipelines/asset_db_hooks.py` — 6 hook fonksiyonu: `record_scan_start()`, `save_subdomains()`, `save_live_hosts()`, `save_endpoints()`, `save_verified_findings()`, `record_scan_finish()`. full_scan.py'ye entegre.

**Tier 1 — New Recon Tools:**

**GitHub Secret Scanner (V7-T1-1):** `src/tools/recon/osint/github_secret_scanner.py` — 22+ regex pattern ile GitHub code search. AWS key, GCP key, Slack token, JWT, private key, DB connection string vb. Org+domain dorking.

**Cloud Storage Enumerator (V7-T1-2):** `src/tools/recon/osint/cloud_enum.py` — S3, Azure Blob, GCS, DigitalOcean Spaces. 40+ permütasyon (dev, staging, backup, prod suffix). HEAD + listing kontrolü.

**Email Security Checker (V7-T1-3):** `src/tools/recon/dns/mail_security.py` — SPF, DKIM (selector1, google, default), DMARC kayıt analizi. MX record extraction. Eksik/zayıf config → bulgu.

**Reverse IP Lookup (V7-T1-4):** `src/tools/recon/dns/reverse_ip.py` — HackerTarget API + DNS PTR ile co-hosted domain keşfi. IP üzerindeki tüm domain'leri bulur.

**Metadata Extractor (V7-T1-5):** `src/tools/recon/osint/metadata_extractor.py` — DuckDuckGo dorking ile doküman keşfi + exiftool ile metadata çıkarma. Author, software, internal path, email sızıntıları.

**Tier 2 — Enhanced Discovery:**

**CDN Detector (V7-T2-1):** `src/tools/recon/tech_detect/cdn_detector.py` — 9 CDN provider (Cloudflare, Akamai, Fastly, CloudFront, Azure CDN, Google Cloud CDN, StackPath, Sucuri, Incapsula). Header signature + CNAME pattern matching.

**CSP Subdomain Discovery (V7-T2-2):** `src/tools/recon/web_discovery/csp_discovery.py` — Content-Security-Policy header'larından domain/subdomain çıkarma. Same-org vs third-party sınıflandırma.

**VHost Fuzzer (V7-T2-3):** `src/tools/recon/web_discovery/vhost_fuzzer.py` — Host header fuzzing ile gizli virtual host keşfi. 35 yerleşik prefix. ffuf delege veya pure-Python httpx fallback. Baseline karşılaştırma.

**403/401 Bypass Engine (V7-T2-4):** `src/tools/scanners/custom_checks/fourxx_bypass.py` — 30+ bypass tekniği: path mutations (trailing slash, double encoding, Spring bypass, nginx off-by-slash), 20+ header bypass (X-Forwarded-For, X-Original-URL, X-Rewrite-URL), 6+ method override.

**Source Map Extractor (V7-T2-5):** `src/tools/recon/web_discovery/sourcemap_extractor.py` — `.map` referansı bulma (comment + header + append), sourceMappingURL indirme, orijinal kaynak çıkarma, 8 secret pattern ile tarama (API key, AWS key, JWT, private key, password, internal URL, GraphQL endpoint, admin path).

**GF Pattern Engine (V7-T2-6):** `src/tools/recon/web_discovery/gf_patterns.py` — 10 kategori (xss, sqli, ssrf, lfi, rce, redirect, ssti, idor, debug, secrets) ile URL sınıflandırma. `classify()`, `filter()`, `filter_interesting()`. Custom pattern ekleme desteği.

**Tier 3 — Diff & Incremental:**

**Diff Engine (V7-T3-1):** `src/analysis/diff_engine.py` — İki scan sonucu karşılaştırması. `DiffEngine.diff()` → `ScanDiffReport` (asset_diff, new_findings, resolved_findings). `generate_markdown()` ile diff raporu.

**Incremental Scan Mode (V7-T3-2):** `src/workflow/pipelines/incremental.py` — `compute_incremental_targets()` ile sadece yeni/değişen asset'leri tarama. `get_last_scan_id()`, `should_rescan_endpoint()`. AssetDB ile entegre delta hesaplama.

**Diff-Based Notification Alerts (V7-T3-3):** `src/integrations/diff_alerts.py` — 5 bildirim türü: 🚨 critical/high findings, 📡 new assets, ⚠️ disappeared assets, ✅ resolved findings, 📊 scan summary. NotificationManager ile entegre.

**Tier 4 — Smart Automation:**

**Dynamic Wordlist Generator (V7-T4-1):** `src/tools/fuzzing/dynamic_wordlist.py` — CeWL-benzeri web scraping + subdomain/endpoint pattern extraction + version expansion (api-v1 → api-v2, v3). 6 framework wordlist (WordPress, Django, Spring, Laravel, Express, Rails).

**Favicon Hash Tech Detection (V7-T4-2):** `src/tools/recon/tech_detect/favicon_hasher.py` — Pure Python MurmurHash3 32-bit. 25+ bilinen hash (Spring Boot, Jenkins, Grafana, Tomcat, K8s Dashboard, Jira, GitLab, SonarQube, Kibana, Prometheus, Vault, Traefik vb.). Shodan uyumlu format.

**GF → Scanner Auto-Routing (V7-T4-3):** `src/tools/scanners/gf_router.py` — GF pattern sınıflandırmasından scanner task'lara otomatik yönlendirme. 10 kategori → 15+ scanner mapping (xss→dalfox/xsstrike, sqli→sqlmap, ssrf→ssrfmap, lfi/rce→nuclei/commix, ssti→tplmap, idor→custom).

**Dry-Run Mode (V7-T4-4):** `src/workflow/pipelines/dry_run.py` — Pipeline'ı çalıştırmadan 8 aşama ve ~60 araç önizlemesi. Profile-aware (`stealth/balanced/aggressive`) rate limit ve parametre ayarları. `dry_run_plan()` + `format_dry_run()`.

### v2.5 Güçlendirmeleri (PROOF-OF-EXPLOIT)

Session 12'de gerçekleştirilen v2.5 iyileştirmeleri — Teorik bulgulardan kanıtlanmış exploitlere geçiş:

**ExploitVerifier Engine:** `src/tools/exploit/exploit_verifier.py` — Merkezî exploit doğrulama orkestratörü. Her bulguyu 4 stratejiden biriyle doğrular: (1) PoC Script — Python sandbox'ta çalıştırma + LLM refinement loop, (2) cURL Command — curl verbose çıktı analizi, (3) Metasploit — CVE-eşleşmeli otomatik modül çalıştırma (12+ CVE mapping), (4) Nuclei Template — re-verification. `ProvenFinding` dataclass ile kanıtlanmış sonuçlar. `verify_batch()` ile toplu, concurrent doğrulama. `_prioritize_candidates()` severity + confidence bazlı sıralama. 9 teknoloji için auxiliary scanner mapping.

**EvidenceAggregator:** `src/reporting/evidence/evidence_aggregator.py` — Her kanıtlanmış bulgu için unified evidence package: evidence.json (metadata), poc_script.py/.sh (PoC kodu), poc_output.txt (çalıştırma çıktısı), http_exchanges.har (HAR 1.2 format), screenshots/ (görsel kanıt), summary.md (insan-okunur özet). `EvidencePackage` dataclass. `collect()` async, `export()` disk'e yazma, `export_all()` toplu.

**Pipeline Phase C Yenilenmesi:** `full_scan.py` HUNTER Mode Phase C tamamen yeniden yazıldı. Eski 8-bulgu limitli PoC loopundan → ExploitVerifier + EvidenceAggregator entegrasyonuna geçildi. Tüm qualifying bulgular doğrulanır (limit yok). 30 dakika toplam timeout. Kanıtlanmış bulgulara `poc_confirmed`, `poc_code`, `poc_evidence`, `evidence_chain_id` alanları eklenir. EvidenceChain integrity hash ile kanıt bütünlüğü.

**Metasploit Pipeline Entegrasyonu:** Phase C'den önce iki yeni adım: (1) Teknoloji bazlı auxiliary scan — tespit edilen 9 teknoloji (apache, tomcat, iis, wordpress, joomla, drupal, jenkins, elasticsearch, phpmyadmin) için otomatik Metasploit auxiliary taraması, (2) CVE auto-exploit — searchsploit/tech_cve_checker bulgularındaki CVE referanslarını otomatik Metasploit modülüyle doğrulama. Güvenli payload'lar (id/whoami) ile sadece PoC düzeyinde çalıştırma.

**FP Layer 6 Full Replay:** `fp_detector._layer6_rerequest_verify()` artık sadece GET değil, orijinal HTTP method'u (POST/PUT/PATCH/DELETE) ile tam replay yapıyor. Request body, headers, payload hepsi dahil. Payload'lı istek + kontrol isteği karşılaştırması. Payload reflection + status/body diff analizi. Reproduced+reflected → +12, reflected → +10, status+body → +10, status → +5, body → +3, identical → -8.

### v2.6 Güçlendirmeleri (NEXT_LEVEL_PLAN_V9)

Session 13'te gerçekleştirilen v2.6 iyileştirmeleri:

**Dead Security Checker Wiring (V9-T0):** `src/workflow/pipelines/full_scan.py` artık 4 previously-dead security modülünü çalıştırır: `jwt_checker.py`, `fourxx_bypass.py`, `http_smuggling_prober.py`, `graphql_deep_scanner.py`. Custom checker fan-out 16 → 20 oldu.

**Dead Recon/OSINT Wiring (V9-T1):** Passive recon'a `github_secret_scanner.py` + `mail_security.py`, active recon'a `cdn_detector.py` + `reverse_ip.py`, enumeration'a `vhost_fuzzer.py`, `cloud_enum.py`, `metadata_extractor.py`, `dynamic_wordlist.py` bağlandı. Böylece 8 previously-written modül üretim pipeline'ına girdi.

**Diff Engine Integration (V9-T2-1):** `src/analysis/diff_engine.py` + `src/integrations/diff_alerts.py` reporting aşamasına bağlandı. Önceki taramaya göre asset/finding diff markdown raporu üretilir ve bildirim kanallarına delta alert gönderilir.

**Secondary Pipeline Timeout Hardening (V9-T2-2):** `src/workflow/pipelines/web_app.py` ve `src/workflow/pipelines/api_scan.py` artık pipeline-level `asyncio.wait_for()` wrapper kullanır. Ayrıca `api_scan.py` içindeki latent integration bug düzeltildi: `ToolExecutor.execute()` unsupported `timeout=` keyword ile çağrılmıyordu; tüm çağrılar güvenli `_execute_tool()` helper'ına taşındı.

### v2.6.2 Güçlendirmeleri (V10 Tier 0 Başlangıcı)

**Module Impact Telemetry (V10-T0-1):** `src/analysis/benchmark.py` artık `tool_execution_counts`, `stage_finding_counts` ve `module_impact` alanlarını persist eder. `full_scan.py` benchmark kaydı bu kalite sinyallerini üretir; rapor/benchmark katmanı hangi modülün gerçek sinyal ürettiğini görünür kılar.

**Full-Scan Regression Guard (V10-T0-2):** `tests/test_integration/test_full_scan_v9_wiring.py` ile passive recon, active recon, enumeration ve vulnerability scan içindeki V9 wired modüller için pipeline-level entegrasyon koruması eklendi. Böylece previously-dead wiring tekrar sessizce bozulamaz.

**Report Fidelity Guard (V10-T0-3):** `src/reporting/report_generator.py` dict tabanlı finding'lerde `screenshot_path`, `impact`/`business_impact`/`impact_analysis` ve multi-tool provenance alanlarını koruyacak şekilde güçlendirildi. Reporting katmanında kanıt veya kaynak aracın sessiz kaybı engellendi; `tests/test_reporting/test_reporting.py` içine regresyon testleri eklendi.

### v2.6.3 Güçlendirmeleri (V12 Integration Hardening)

**Diff Alert Channel Wiring (V12-P0-1):** `src/integrations/notification.py` içine `build_notification_manager()` ve `load_notification_config()` eklendi. Böylece `full_scan.py` diff alert aşamasında boş `NotificationManager()` oluşturmak yerine `config/settings.yaml` içindeki terminal/slack/telegram/discord kanallarını gerçek webhook/token değerleriyle instantiate eder. `tests/test_integration/test_notification_wiring.py` ile wiring regresyon koruması eklendi.

**Quick Recon Timeout Hardening (V12-P0-2):** `src/workflow/pipelines/quick_recon.py` artık web_app/api_scan ile aynı pipeline-level `_execute_tool()` pattern'ını kullanır. dig/whois/subfinder/httpx/nmap/whatweb çağrıları `asyncio.wait_for()` ile sarıldı; timeout'lar artık stage içinde güvenli şekilde loglanır ve stall'lar cascade etmez. `tests/test_workflow/test_quick_recon.py` ile timeout ve state update davranışı koruma altına alındı.

**CVSS Vector Validation Guard (V12-P0-3):** `src/reporting/report_generator.py` içindeki `ReportFinding.cvss_vector` alanı artık `SeverityCalculator.parse_vector()` ile validate edilir. Malformed vector'ler rapora girmeden düşürülür; finding kaynaklı geçerli vector varsa korunur, bozuksa güvenli default vector'e fallback yapılır. `tests/test_reporting/test_reporting.py` içine geçerli/geçersiz CVSS vector regresyon testleri eklendi.

**Brain Context Budget Guard (V12-P1-1):** `src/brain/engine.py` artık prompt gönderilmeden önce yaklaşık token bütçesi hesaplar, prompt+completion toplamı model `context_length` sınırını aşarsa user mesajını kırpar ve completion bütçesini daraltır. Streaming inference sırasında completion token tahmini izlenir; remote/local stream budget aşıldığında akış kontrollü şekilde durdurulur. `tests/test_brain/test_brain.py` içine context-fit regresyon testleri eklendi.

### v2.6.4 Güçlendirmeleri (V13 Deep Audit + Integration Wiring)

**Tool Failure Visibility (V13-H1):** `src/workflow/pipelines/full_scan.py` içindeki 48 araç başarısızlık logu `logger.debug()` → `logger.warning()` olarak yükseltildi. Operatörler artık güvenlik modülleri sessizce başarısız olduğunda uyarı alır.

**Brain Prompt Credential Sanitization (V13-H2):** `src/brain/intelligence.py` içine `_sanitize_prompt()` fonksiyonu eklendi. 16 hassas veri kalıbı (api_key, password, bearer, aws_secret, github_token, database_url vb.) LLM'e gönderilmeden önce `***REDACTED***` ile maskelenir. Cache key hesaplamasından SONRA uygulanır, böylece sanitizasyon cache davranışını etkilemez.

**BrainRouter Full Wiring (V13-H3):** `BrainRouter` artık `main.py → full_scan.py → orchestrator → IntelligenceEngine` zinciriyle bağlı. `_brain_call()` metodu `task_type` parametresi alır; router varsa `router.route(task_type)` ile brain seçimi yapılır. Tüm 10 `_brain_call` çağrısı task_type anotasyonlarıyla güncellendi: strategy(2), analyze(2), tool_select(1), fp_check(1), exploit(2), report(1), triage(1).

**StateMachine Orchestrator Guard (V13-T0-3):** `src/workflow/orchestrator.py` artık `StateMachine` import edip `__init__`'de oluşturur ve `start()` ile başlatır. Stage döngüsünde her aşamadan önce `can_transition()` ile geçiş geçerliliği kontrol edilir. Geçersiz geçişler WARNING olarak loglanır ama yürütme engellenmez.

**ResponseIntel → FPDetector Downstream (V13-T0-1):** `FPDetector.__init__()` artık `response_intel: dict` parametresi kabul eder. Layer 5 WAF tespiti, pipeline-level ResponseIntel verilerindeki WAF/CDN sinyallerini kullanarak zenginleştirildi. `full_scan.py` FP aşaması `state.metadata["response_intel"]` verilerini FPDetector'a aktarır.

**DecisionEngine select_tools() Wiring (V13-T0-2):** `handle_vulnerability_scan()` artık tarama başlangıcında `DecisionEngine.select_tools()` çağırır. ResponseIntel'den algılanan teknolojiler ve `state.technologies` context olarak geçirilir. WordPress/PHP gibi teknoloji-spesifik araçlar otomatik eklenir. Sonuçlar loglara kaydedilir.

### v2.6.5 Güçlendirmeleri (V13 Agentic Branching Phase 1)

**Controlled Agentic Next-Action Loop (V13-T1-1 Phase 1):** `src/brain/intelligence.py` içine `NextActionDecision` modeli ve `decide_next_action()` metodu eklendi. Bu metot `build_next_action_prompt()` üzerinden findings-so-far, tamamlanan araçlar, kalan araçlar ve geçen süreyi değerlendirerek yalnızca mevcut pipeline içindeki güvenli aksiyonları seçer: araç atlama, derinlemesine hedef öncelikleme ve sonraki uygun araç önerisi.

**VulnScan Mid-Stage Branch Point Wiring:** `src/workflow/pipelines/full_scan.py` artık ilk geniş tarama dalgasından (nuclei/nikto/searchsploit) sonra agentic karar noktası çalıştırır. LLM kararı `_skipped_tools` set'ine aktarılır, `deep_dive_target` çözülerek `endpoints` ve `brain_vectors` içine enjekte edilir, metadata altında `agentic_next_action` olarak saklanır.

**Agentic Skip Enforcement:** Aynı agentic karar, sonraki aşamalarda gerçekten uygulanır: `dalfox`, `corsy`, `crlfuzz` ve 21 paralel custom checker artık agentic skip listesine saygı duyar. Böylece model tavsiye veren değil, güvenli sınırlar içinde gerçek akışı optimize eden bir orkestratör rolü üstlenir.

### v2.6.6 Güçlendirmeleri (V13 Session Auto-Resume Wiring)

**Main Scan Auto-Resume (V13-T1-2):** `src/cli.py` içindeki ana `scan` komutu artık aynı hedef için yarım kalmış oturumları `SessionManager.find_incomplete_sessions(target=...)` ile arar. `autonomous` modda en güncel uygun oturum otomatik resume edilir; `semi-autonomous` modda kullanıcıya tek seferlik resume onayı sorulur.

**SessionManager Full Pipeline Wiring:** `src/main.py` artık `SessionManager` oluşturup `build_full_scan_pipeline()` üzerinden `WorkflowOrchestrator` içine enjekte eder. Böylece normal `scan` akışı da checkpoint, crash recovery ve resume için gereken session persistence zincirini gerçekten kullanır.

**Deterministic Incomplete Session Discovery:** `src/workflow/session_manager.py` içindeki `find_incomplete_sessions()` artık opsiyonel `target` filtresi ve `last_checkpoint_at/resumed_at/started_at/created_at` tabanlı recency sorting kullanır. Böylece auto-resume en alakalı ve en güncel oturumu seçer.

### v2.6.7 Güçlendirmeleri (V13 Cross-Scan Learning Memory)

**KnowledgeBase-Backed Scan Learning (V13-T1-3):** `src/brain/memory/knowledge_base.py` içine `record_scan_learning()` ve `get_learning_snapshot()` eklendi. Scan sonunda teknoloji yığını, productive tool'lar, doğrulanmış vuln tipleri, false positive kalıpları ve tool effectiveness metrikleri tek bir kalıcı öğrenme katmanına yazılıyor; ayrı bir depo açmak yerine mevcut `KnowledgeBase` genişletildi.

**Historical Learning Injection:** `src/workflow/pipelines/full_scan.py` attack surface aşamasında, tespit edilen teknoloji stack için `KnowledgeBase` üzerinden tarihsel öğrenme snapshot'ı çekiyor ve bunu `state.metadata["historical_learning"]` içine koyuyor. Böylece tarama başlamadan önce hangi araçların ve hangi vuln family'lerinin benzer stack'lerde üretken olduğu pipeline tarafından görülebiliyor.

**Agentic Decision Context Enrichment:** `src/brain/prompts/triage_prompts.py` ve `src/brain/intelligence.py` artık next-action prompt'una `historical_learning` bağlamını da ekliyor. Mid-stage agentic branching kararı, yalnızca mevcut bulgulara değil, önceki benzer taramalarda işe yarayan araç/vuln sinyallerine de bakarak veriliyor.

### v2.6.8 Güçlendirmeleri (V13 Operator Watch + Safe Run Validation)

**Scan Watch Command:** `src/workflow/scan_monitor.py` ve `src/cli.py` içine yeni operator watch akışı eklendi. `whai watch [session_id] --every-minutes 20 --iterations N` komutu session metadata + günlük log dosyalarını (`errors`, `tools`, `brain`, `whai`) okuyarak uyarı/timeout/hata sinyallerini özetler, öneriler üretir ve periyodik gözlem sağlar.

**Observation Notes Persistence:** `src/workflow/session_manager.py` içine `append_note()` eklendi. Watch çıktıları artık oturum metadata notlarına ve `output/sessions/<session_id>/monitor_notes/` altındaki markdown gözlem dosyalarına yazılır; böylece uzun taramalarda operatör denetimi ve sonradan iyileştirme planı için kalıcı iz bırakılır.

**Safe CLI Validation Path:** Proje bağımlılıkları sistem Python'una zorla kurulmadan, repo-local `.venv` üzerinden `whai watch --help` ve `whai scan example.com --dry-run` ile doğrulandı. Böylece canlı hedefe dokunmadan scan/watch yürütme zinciri test edilmiş oldu.

### v2.7.0 Güçlendirmeleri (V14/V15 Production Readiness)

**Phase 1 — 9 Critical Bug Fixes:** AssetDB optional `name` parametresi düzeltildi, SshAudit `binary_name` düzeltildi, ANSI regex strip cursor movement desteği eklendi, brain-down deadlock düzeltildi (auto-recovery after configurable timeout), executor default timeout eklendi, scope validator halt-on-empty, finding dedup cross-tool normalizasyonu, checkpoint JSON serialization.

**Phase 2 — Dead Code Wiring (7 yeni wrapper + 3 entegrasyon):** `assetfinder_wrapper.py`, `crt_sh_wrapper.py`, `dnsx_wrapper.py`, `fierce_wrapper.py`, `dirb_wrapper.py`, `feroxbuster_wrapper.py`, `wfuzz_wrapper.py` oluşturuldu ve `register_tools.py` üzerinden pipeline'a bağlandı. `MultiToolVerifier` FP doğrulama entegrasyonu, HTML rapor çıktısı ve `findings.json` export'u aktif edildi.

**Phase 3 — Pipeline Robustness (5 item):** Scope boşsa pipeline durdurma, StateMachine reset-on-error, brain critique timeout guard, checkpoint retry (JSON serialize hata yakalama), amass async timeout koruması.

**Phase 4 — New Capabilities (5 item):** FP patterns 21→44+ genişletme (Nuclei tech-detect, SearchSploit noise, WAF/CDN artifacts, CMS FPs, CRLF/LFI/IDOR/timing/info-disclosure kalıpları). OOB metadata enrichment (`interactsh_callback`, `oob_domain`, `oob_protocol`, `blind_verification`, `interaction_type`). `whai submit` CLI komutu (HackerOne/Bugcrowd/generic, draft mode). Incremental scan CLI flag.

**Phase 5 — Test Hardening (5 item):** 12 auth_session async test arızası düzeltildi (pytest-asyncio → `asyncio.run()` pattern). 10 Phase-1 regresyon testi, 6 evidence pipeline testi eklendi. `.coveragerc` ile %30 minimum kapsam eşiği tanımlandı. **Test suite: 298 → 341 tests, 0 failures.**

**Phase 6 — SSH/Brain Recovery (6 item):** SSH tunnel auto-recovery (`_ensure_ssh_tunnel()`), pre-scan `verify_brain_ready()` 3-aşamalı kontrol, brain-down auto-recovery timeout, `ssh_tunnel.sh watch` watchdog, ConnectError retry mekanizması, detaylı hata mesajları.

**Phase 7 — Timeout Hardening (4 item):** Stage-level `asyncio.wait_for()` tüm pipeline aşamalarına uygulandı, LLM inference timeout guard, tool-level timeout profil bazlı ölçekleme (stealth 2x, aggressive 0.6x), yapay bulgu limitleri kaldırıldı.

### v2.7.1 Güçlendirmeleri (Authenticated Scanning — Phase 1)

**FP Layer 6 Auth Injection (P1-5):** `src/fp_engine/fp_detector.py` artık `auth_headers: dict[str, str] | None` parametresi kabul eder. Layer 6 `_layer6_rerequest_verify()` hem payload request hem de control request'e auth header'ları enjekte eder. Böylece authenticated bulguların 401/403 alma nedeniyle yanlış FP olarak işaretlenmesi (-8 score) engellenir. Finding-specific header'lar auth header'lara göre öncelik kazanır (`setdefault` pattern).

**Pipeline Auth Session Refresh (P1-1):** `src/workflow/orchestrator.py` stage loop'unda her handler çağrısından önce `ensure_valid()` ile auth session refresh yapılır (30s timeout). Uzun taramalarda token expiry nedeniyle sessiz auth kaybı engellenir.

**Multi-Role IDOR Testing (P1-4):** `src/tools/scanners/custom_checks/idor_checker.py` artık N-role pairwise testing destekler. `auth_roles` listesindeki her A→B rol çifti (A≠B) ve her rol vs unauthenticated test edilir. Bulgu başlıklarında ve metadata'da rol isimleri yer alır. `src/tools/auth/session_manager.py` içine `build_auth_roles()` fonksiyonu eklendi — scope YAML `auth.roles` listesini parse eder, parent auth field'larını inherit eder.

**Scope YAML Multi-Role Auth (P1-2):** `config/scopes/example_scope.yaml` artık `roles:` listesi ile çoklu rol tanımı desteğini dokümante eder. `AuthConfig` dataclass'ına `role_name: str` alanı eklendi.

**WorkflowState First-Class Auth Fields:** `WorkflowState(BaseModel)` artık `auth_headers: dict[str, str]` ve `auth_roles: list[dict[str, Any]]` alanlarına sahip. Auth verileri artık `metadata` dict'ine gömülü kalmak yerine first-class field olarak erişilebilir. `orchestrator.run()` extra_metadata'dan promote eder; `full_scan.py` first-class field'ı tercih eder, metadata'ya fallback yapar.

**Pipeline Wiring:** `src/main.py` artık `build_auth_roles()` ile scope YAML'dan multi-role config parse eder, her rolü authenticate eder ve `extra_metadata["auth_roles"]` olarak pipeline'a geçer. `full_scan.py` IDOR ve FPDetector aşamaları bu verileri kullanır. **Test suite: 419 tests, 0 failures.**

### v2.7.2 Güçlendirmeleri (Finding Quality Revolution — Phase 2)

**Nuclei Template Validation Overhaul (P2-1):** 207 custom Nuclei template derin denetimden geçirildi. 6 düzeltilmez template `_disabled/` klasörüne taşındı (race-condition-coupon, parameter-pollution, no-rate-limit-login, session-fixation, dns-rebinding, http2-smuggling-detect — tek Nuclei isteğiyle test edilemez zafiyet türleri). 5 template düzeltildi: ters `negative:true` mantığı (sqli-union-columns), regex quoting hataları (apikey-in-url, hardcoded-secrets-js, sqli-json-body), pozitif kanıt eksiklikleri (jwt-none-algorithm, xxe-injection). `nuclei_wrapper.py` confidence hesaplaması severity-based statik map'ten evidence-based puanlamaya geçirildi (base 50 + extracted_results/curl/matcher/endpoint/cve bonusları, 20-95 aralığı). `nuclei_template_writer.py` validator'a quality gate eklendi: HIGH/CRITICAL severity template'ler pozitif content matcher olmadan reject edilir.

**CORS Checker Severity Fix (P2-2):** `cors_checker.py` artık `Access-Control-Allow-Credentials: true` olmadan origin reflection'ı LOW severity + confidence 40 olarak raporlar (eskiden HIGH + 60). Credential'sız CORS data theft'i mümkün olmadığından severity doğru yansıtılır.

**Brain Hypothesis FP Patterns (P2-3):** `known_fps.py` içine `FP-BRAIN-001` (finding_type=hypothesis → -25 penalty) ve `FP-BRAIN-002` (needs_verification tag → -20 penalty, verify action) eklendi. Brain hipotezleri artık FP engine tarafından da değerlendirilir.

**Multi-Parameter Deep Probe Injection (P2-4):** `deep_probe.py` `_default_payloads()` artık tek parametre yerine tüm parametreleri (max 5) için payload üretir. `_send_probes()` rotasyonlu parametre seçimi kullanır — LLM param belirtmediğinde sırayla tüm parametrelere inject edilir.

**Confidence-Based Severity Calibration (P2-5):** `full_scan.py` confidence calibration'dan sonra severity downgrade mantığı eklendi: confidence<30 + severity≥MEDIUM → LOW; confidence<40 + severity≥HIGH → MEDIUM; confidence<50 + severity=CRITICAL → HIGH. Düşürülen bulgulara `original_severity` ve `severity_downgrade_reason` alanları eklenir.

**FP Pattern Library Expansion (P2-6):** `known_fps.py` 42→100 pattern'a genişletildi. Yeni kategoriler: Brain hypothesis (2), CORS-no-ACAC (1), JWT (2), GraphQL (2), Deserialization (1), Race condition (1), Nuclei tech-detect (1), SearchSploit noise (1), Security headers (2), Cache poisoning (1), Prototype pollution (1), Subdomain takeover (2), Dalfox XSS (1), Nikto (2), CRLF (1), LFI (2), IDOR (1), Info disclosure (2), HTTP method (2), WAF challenge (1), SSTI (1), SSRF (2), RCE (1), XXE (1), Cookie (2), Rate limiting (1), Open redirect (1), Commix (1), Mass assignment (1), SQLi deep probe (1), Nuclei info (1), HTTP smuggling (1), BOLA (1), Deep probe (1), XSS stored (1), CORS same-org (1), CSP report-only (1), WPScan (2), Tplmap (1), SQLMap (1), CSRF (2), NoSQLi (1), Host header (1), Timing (1), Nuclei duplicate (1). **Test suite: 419 tests, 0 failures.**

### v2.7.3 Güçlendirmeleri (Brain Intelligence Upgrade — Phase 3)

**Prompt Engineering Overhaul (P3-1):** `engine.py` JSON enforcement güçlendirildi — soft "IMPORTANT" mesajı yerine çok satırlı CRITICAL direktif: "You MUST return ONLY valid JSON... Start with `{` and end with `}`... parseable by json.loads()". Yeni `_brain_call_json()` metodu eklendi — `_brain_call(json_mode=True)` + `_safe_json_parse()` sarmalayıcısı, parse başarısız olursa düzeltme prompt'u ile otomatik retry. 10 caller migrate edildi: `analyze_recon_and_plan`, `generate_dynamic_test_cases`, `decide_next_action`, `suggest_tool_config`, `analyze_tool_output`, `verify_finding`, `generate_nuclei_template`, `generate_poc`, `enrich_report_finding`, `suggest_rescan`. 4 yeni `_from_dict` parser varyantı eklendi. 5 prompt dosyasına few-shot kalibrasyon örnekleri eklendi: `triage_prompts.py` (4 örnek), `analysis_prompts.py` (2), `exploit_prompts.py` (1), `recon_prompts.py` (1), `report_prompts.py` (1).

**Agentic Decision Engine Enhancement (P3-2):** `NextActionDecision` modeline 4 yeni alan: `deep_dive_tool` (str), `change_strategy` (str — stealth/balanced/aggressive), `retry_with_auth` (bool), `request_oob_check` (bool). İzin verilen aksiyonlar 5→9'a genişletildi: continue, skip_to_next_stage, deep_dive, deep_dive_tool, change_strategy, retry_with_auth, request_oob_check, pause, complete. `full_scan.py` yeni aksiyon handler'ları: `agentic_strategy_change`, `agentic_retry_with_auth`, `agentic_request_oob_check` metadata'ya yazılır.

**Cross-Finding Reasoning Enhancement (P3-3):** `correlation_engine.py` `detect_chains_llm()` yeniden yazıldı: bulgu limiti 30→50, bulgulardan teknoloji tespiti, saldırı anlatısı yapısında prompt, `_brain_call_json()` ile retry güvenilirliği, timeout 120s→180s. Yeni `_build_chain_hints()` statik metodu eklendi — 5 teknoloji-farkında zincir ipucu kalıbı: (1) SSRF→cloud metadata credential pivot, (2) XSS+CORS/CSRF→session hijack, (3) SQLi+auth bypass→data breach, (4) Open redirect+OAuth→token theft, (5) JWT+IDOR→privilege escalation.

**Recon Intelligence Amplification (P3-4):** `intelligence.py` `analyze_recon_and_plan()` tamamen yeniden yazıldı. 3 yeni statik yardımcı: `_cluster_urls()` — URL'leri path pattern'a göre gruplar (dinamik segmentler `{id}` ile değiştirilir, max 30 cluster), `_compact_tech_stack()` — tüm host'ların teknolojilerini tek birleşik özette toplar (frameworks/servers/languages/other), `_compact_ports()` — portları standart/standart-dışı olarak sınıflar. Token bütçesi yönetimi: 8K token hedefi, aşıldığında verileri otomatik kırpar ve condensed prompt üretir (eski 24K uyarı-only yerine). URL dedup 20 path→30 pattern cluster'a genişletildi.

**LLM Fallback Brain (P3-5):** `BrainEngine.__init__()` artık opsiyonel `fallback_config: ModelConfig` kabul eder. 3. kademe acil durum fallback'i: primary VE secondary circuit breaker'lar OPEN olduğunda hafif yerel model (ör: Qwen2.5-7B-Q4) devreye girer. `_try_fallback_inference()` metodu eklendi — lightweight model ile triage/tool selection yapabilir. `_init_fallback()` metodu local veya remote backend destekler. `has_fallback` property'si eklendi. `config/settings.yaml` içine `brain.fallback` bölümü eklendi (context_length: 8192, max_tokens: 1024, temperature: 0.3). `src/main.py` fallback config'i koşullu olarak yükler (model_path veya api_url dolu ise). `shutdown()` fallback kaynakları temizler. **Test suite: 419 tests, 0 failures.**

### v2.7.4 Güçlendirmeleri (Tool Effectiveness & New Capabilities — Phase 4)

**Technology-Aware Tool Selection (P4-2):** `decision_engine.py` artık teknoloji-farkında araç seçimi yapıyor. `_TECH_TOOL_MAP` class değişkeni: 80+ teknoloji→araç eşlemesi 13 kategori altında (CMS, Languages, Frameworks, Servers, API, Auth, Databases, Infrastructure, Network, TLS). `_TECH_ONLY_TOOLS`: 17 araç→gerekli-teknoloji eşlemesi (wpscan→wordpress, joomscan→joomla, enum4linux→smb vb.). Yeni `filter_irrelevant_tools()` metodu: gerekli teknolojisi tespit edilmemiş araçları otomatik filtreler. `select_tools()` adım 5b olarak entegre.

**WAF Bypass Intelligence Loop (P4-3):** `waf_strategy.py` önemli ölçüde genişletildi. 11 payload transform fonksiyonu: double_url_encode, case_randomize, unicode_normalize (confusable chars: <→＜), html_entity_mix, url_encode_selective, sql_comment_injection (/*!UNION*/), inline_comment (un/**/ion), null_byte_insertion, whitespace_variation, chunked_encoding. `_TRANSFORM_FUNCS` dict: 12 entry. `transform_payload()` tekil dönüşüm, `generate_bypass_variants()` WAF-spesifik 5 varyant üretimi, `is_waf_blocked()` status+body pattern tespit.

**JavaScript Deep Analysis (P4-4):** `js_analyzer.py` Shannon entropy tabanlı secret detection ve DOM XSS source/sink tespiti ile güçlendirildi. `_shannon_entropy()` bits/char hesaplama, `_detect_high_entropy_secrets()` threshold 4.5 (context ile 4.0), sk_live/JWT gibi keyler yakalıyor. `_DOM_SOURCES` (11 entry: document.URL, location.hash, postMessage vb.), `_DOM_SINKS` (14 entry: innerHTML, eval, document.write, jQuery.html vb.), `_detect_dom_xss_patterns()` 500 char proximity analizi.

**GraphQL Deep Exploitation (P4-5):** `graphql_deep_scanner.py` 8→12 test fonksiyonuna genişletildi. `_test_introspection_bypass()`: 7 bypass tekniği (standard, GET, newline-padded, fragment, aliased, __type, uppercase). `_COMMON_GQL_FIELDS` (98 entry) ve `_COMMON_GQL_MUTATIONS` (37 entry) ile `_test_field_bruteforce()` ve `_test_mutation_discovery()`. `_test_persisted_query_bypass()`: APQ hash bypass + arbitrary query registration testi.

**Cloud & Infrastructure Security (P4-6):** `cloud_checker.py` endpoint'leri 35→64'e genişletildi, 8 kategori (kubernetes, cicd, container, monitoring, cloud_meta, secrets, config, serverless). Yeni: .git/HEAD, .svn/entries, .hg/store, serverless functions, pprof, expvar, elmah.axd, phpinfo.php, swagger-ui, graphiql vb. `_TECH_CATEGORY_FILTER` ile teknoloji-farkında filtreleme — PHP/Apache stack'te k8s/cicd/container/serverless atlanır.

**CI/CD Security Checks (P4-7):** YENİ MODÜL `cicd_checker.py`. 44 CI/CD endpoint 10 platformda (Jenkins/19, GitLab/9, generic/6, Gitea/3, GitHub/2 vb.). `_CICD_SIGNATURES` 10 platform, `_SECRET_LEAK_PATTERNS` 10 regex (API key, AWS key, GitHub PAT, JWT vb.), `_INTERNAL_PKG_PATTERNS` 4 dependency confusion göstergesi. 3 faz: endpoint probe → dependency confusion → build log scan. Platform-farkında endpoint filtreleme.

**HTTP/2 & HTTP/3 Testing (P4-8):** YENİ MODÜL `http2_http3_checker.py`. 5 test fonksiyonu: `_check_alpn()` (ALPN negotiation), `_check_alt_svc()` (HTTP/3/QUIC via Alt-Svc), `_check_h2c_smuggling()` (3 H2C upgrade header variant × 7 sensitive path), `_check_protocol_downgrade()` (HSTS + includeSubDomains), `_check_h2_connect()` (CONNECT tunneling 3 internal target).

**Benchmark Lab Suite (P4-1):** `docker/benchmark-lab.yaml` ile 7 vulnerable-by-design lab: DVWA (8081), Juice Shop (8082), WebGoat (8083), VAmPI (8084), crAPI (8085), DVGA (8086), NodeGoat (8087). `scripts/benchmark_runner.py` ile TPR/FPR ölçüm altyapısı — 6 lab için expected findings manifest, vuln type normalization, per-class detection metrikleri, Markdown benchmark raporu.

**Pipeline Wiring:** Her iki yeni modül (cicd_checker, http2_http3_checker) `full_scan.py` pipeline'ına bağlandı. Custom checker fan-out 22→24'e çıktı. Agentic remaining tools ve tool-to-vuln mapping güncellendi. **Test suite: 419 tests, 0 failures.**

### v2.7.5 Güçlendirmeleri (Infrastructure Hardening — Phase 5)

**P5-1: Silent Exception Audit:** Tüm kod tabanındaki 18 `except...pass` bloğu `logger.warning()` ile değiştirildi. 7 pipeline/brain dosyasındaki 85 `except` bloğunda `logger.debug()` → `logger.warning()` yükseltmesi yapıldı. Sessiz hata gizleme tamamen elimine edildi.

**P5-2: Timeout Architecture Hardening:** 3-tier timeout mimarisi (orchestrator stage / executor tool / HTTP client) denetlendi ve 5 kritik boşluk kapatıldı: `cicd_checker.py` AsyncClient'a `httpx.Timeout(timeout, connect=10)` + gather için `asyncio.wait_for(timeout+30)` eklendi, `cloud_checker.py` AsyncClient timeout eklendi, `api_fuzzer.py` fonksiyon-level 1200s timeout'u `per_request_timeout = min(timeout, 30.0)` ile düzeltildi (main client + BOLA check), `exploit_verifier.py` batch gather'a 1800s `asyncio.wait_for` wrapper eklendi.

**P5-5: Security Hardening:** 4 güvenlik açığı kapatıldı: `nmap_wrapper.py` — `os.chmod(xml_path, 0o666)` kaldırıldı (mkstemp varsayılan 0o600 yeterli), `base.py` — `execute_command()` içine `resource` tabanlı `_set_rlimits()` preexec_fn eklendi (RLIMIT_CPU timeout-based, RLIMIT_AS 2GB, RLIMIT_FSIZE 100MB), `mitmproxy_wrapper.py` — hardcoded `/tmp/whai_capture.flow` yerine güvenli temp dizin (0o700 permissions + PID-based filename), `zaproxy_wrapper.py` — hardcoded API key yerine `secrets.token_hex(16)` fallback.

**P5-3: Test Coverage Expansion:** 10 yeni test dosyası yazıldı, 208 yeni test eklenerek test suite 419→627 teste çıkarıldı. Kapsanan yeni modüller: `scope_validator.py` (20 test — domain/wildcard/IP/CIDR/URL scope, exclusions, batch ops), `severity_calculator.py` (16 test — CVSS v3.1 scoring, vector parse, estimate, context overrides), `known_fps.py` (18 test — 100+ pattern, operators, filters, brain hypothesis), `waf_strategy.py` (30 test — 11 transform fonksiyonu, bypass variants, rate adjustment, WAF detection), `correlation_engine.py` (26 test — dedup, grouping, chains, host risk, OOB, markdown), `attack_surface.py` (28 test — scoring, vectors, host/endpoint add, constants), `js_analyzer.py` (24 test — entropy, DOM XSS source/sink, secret/cloud/endpoint detection), `cicd_checker.py` (18 test — endpoints, secret filtering, platform filtering), `http2_http3_checker.py` (5 test — H2C headers, sensitive paths, async signature), `decision_engine.py` (22 test — tool selection, tech filtering, transitions, abort, constants), `state_machine.py` (26 test — normal/skip/abort transitions, guards, callbacks, history, elapsed time). **Test suite: 627 tests, 0 failures.**

### v2.7.6 Güçlendirmeleri (Scan Quality & Phase 0 Critical Fixes)

**Phase 0 — 6 Critical Bug Fixes (Shopify Scan Root-Cause Analysis):**

**P0-FIX: Confidence/Confidence_Score Dual-Key Sync:** Gerçek Shopify taraması analizinde tüm doğrulanmış bulguların `confidence=None` olduğu keşfedildi. Kök neden: `_finding_to_dict()` içindeki `d.pop("confidence")` anahtarı yok ediyordu ve FP analizi sadece `confidence_score` set edip `confidence`'ı senkronize etmiyordu. 4 kod yolunda (OOB fast-track, verdict success, timeout, exception fallback) + unverified fallback'te her iki anahtar senkronize edildi. `json_formatter.py` ve `technical_detail.py` artık `confidence_score` öncelikli okur, `confidence`'a fallback yapar.

**P0-1: Dynamic Test Case Generation Fix:** `_safe_json_parse()` dönüş tipi `dict | list | None` olarak düzeltildi; `extract_json(expect_array=True)` fallback eklendi. `_brain_call_json()` düzeltme prompt'u artık hem `{...}` nesneleri hem `[...]` dizilerini destekler. Race condition checker: dinamik test case yokken heuristic endpoint fallback (14 pattern: /checkout, /purchase, /redeem vb.) + uyarı logu. Boş/parse-edilemeyen checker türleri için uyarı logu eklendi.

**P0-2: Error Visibility Restoration:** `orchestrator.py` state serializasyonu `metadata`, `technologies` ve `tools_run` alanlarını tamamen atlıyordu — Shopify taramasındaki boş metadata'nın KÖK NEDENİ. Üç alan serializasyon dict'ine eklendi. Tarama sonunda kapsamlı özet logu eklendi (süre, profil, hostlar, bulgular, başarısız araçlar).

**P0-3: SearchSploit FP Elimination:** `_extract_version_from_title()` ve `_versions_compatible()` metotları eklendi. `_is_relevant_to_tech()` minimum hedef uzunluğu 2→3. Teknoloji bağlamı olmadan: severity LOW'a, confidence 15.0'a düşürüldü. Text fallback parser: confidence 65→20, severity LOW'a cap, "unverified" etiketi.

**P0-4: SPA Detection Engine:** Zaten uygulanmıştı! `src/utils/spa_detector.py` (6.3KB), `full_scan.py` satır 2822'de entegre, `state.metadata["is_spa"]`, FP detector satır 287'de catch-all penaltı. Değişiklik gereksiz.

**P0-5: PoC Verification Timeout Fix:** Profil bazlı yapılandırılabilir hale getirildi: STEALTH=600s, BALANCED=900s, AGGRESSIVE=1200s. `full_scan.py` ExploitVerifier instantiation'ında uygulandı.

**P0-6: Brain Cache LRU Fix:** Zaten uygulanmıştı! `OrderedDict` + `move_to_end()` (LRU hit), `popitem(last=False)` (LRU eviction), 10-dk TTL, async lock. Değişiklik gereksiz.

**P5-6: Tool Registry Dedup:** `register()` aynı sınıf tekrar kaydında sessizce atlar (erken return), farklı sınıf çakışmasında her iki sınıf adıyla uyarı loglar ve üzerine yazar.

**Regression Test Suite:** 24 yeni test eklendi: confidence dual-key sync (2), _safe_json_parse array/object/markdown/edge (7), SearchSploit relevance/severity/version (10), state serialization (1), registry dedup (2), race condition heuristic (2). **Test suite: 627 → 651 tests, 0 failures.**

### v2.7.7 Güçlendirmeleri (Continuous Operation — Phase 6)

**Phase 6 — Continuous Operation (5 modül, 2 CLI komutu, 3 pipeline entegrasyonu):**

**P6-3: GlobalFindingStore (Cross-Scan Deduplication):** `src/analysis/global_finding_store.py` — Merkezî, cross-scan bulgu dedup sistemi. SQLite WAL mode, thread-safe per-thread connections. `finding_hash()` → sha256 prefix (16-char hex) bazlı kanonik hash: `canonical_vuln_type||normalised_url||param||cve`. 60+ vuln-type synonym eşlemesi (`_VULN_SYNONYMS`). URL normalizasyonu (lowercase scheme+host, sort query params, strip fragment, strip trailing slash). `FindingStatus` enum: new/recurring/regression/resolved. Full lifecycle tracking: new → recurring → resolved → regression. `record()`, `record_batch()`, `lookup()`, `mark_resolved_not_in_scan()`, `get_finding()`, `get_new_findings()`, `get_regressions()`, `get_stats()`, `count()`. `full_scan.py handle_reporting()` entegrasyonu: tüm bulgular `record_batch()` ile kaydedilir, resolved bulgular `mark_resolved_not_in_scan()` ile işaretlenir, istatistikler `state.metadata["global_finding_stats"]` içine yazılır.

**P6-5: ScanProfiler (Performance Instrumentation):** `src/analysis/scan_profiler.py` — Per-stage ve per-tool zamanlama enstrümantasyonu. `StageTiming` (stage_name, duration_s, tools_run, findings_produced), `ToolTiming` (tool_name, duration_s, success, findings_count), `Bottleneck` (category, name, duration_s, pct_of_total, recommendation). `ScanProfiler`: `start_scan()`, `end_scan()`, `stage(name)` context manager, `record_stage()`, `record_tool()`, `generate_report()` → `PerformanceReport`, `to_dict()`. Darboğaz tespiti: stage >30% total+>60s, tool >120s+0 findings, all-failed tools. `_generate_recommendations()`: dead weight araçlar, en üretken araç, uzun sıfır-bulgu aşamaları. `full_scan.py handle_reporting()` entegrasyonu: `state.stage_results` ve `state.tools_run` verilerinden sahne/araç zamanlamaları yeniden kurulur, `performance_report.md` rapor dizinine kaydedilir.

**P6-1: ContinuousMonitor (Scheduling Loop):** `src/workflow/continuous_monitor.py` — Sürekli hedef izleme döngüsü. İlk iterasyon full scan, sonrakiler incremental. `GlobalFindingStore` ile cross-scan dedup, `DiffEngine` ile asset/finding diff, `NotificationManager` ile bildirim. SIGINT/SIGTERM ile graceful shutdown (asyncio.Event). `run(interval_minutes=120, max_iterations=0)` → sonsuz veya N iterasyon, summary dict döner. CLI: `whai monitor <target> [--interval 120] [--max-iterations 0] [--scope FILE] [--profile balanced]`.

**P6-4: AutoDraftGenerator (Report Drafting):** `src/reporting/auto_draft.py` — Per-finding HackerOne/Bugcrowd tarzı taslak rapor üreteci. `_CVSS_DEFAULTS` (17 vuln type), `_CWE_DEFAULTS` (17 mapping). `should_draft()`: HIGH/CRITICAL her zaman, MEDIUM sadece confidence≥80. `generate_draft()` markdown dosya kaydeder. `_render_hackerone()`: Summary, Severity, Steps to Reproduce, HTTP Request/Response, PoC, Evidence, Impact, Fix, References. `_render_bugcrowd()`: VRT format, priority P1-P5 eşlemesi. `_impact_text()` ve `_remediation_text()` 7 vuln türü için. `full_scan.py handle_reporting()` entegrasyonu: qualifying bulgular için draft dosyaları oluşturulur, yollar `state.reports_generated` listesine eklenir.

**P6-2: CampaignManager (Multi-Target Campaigns):** `src/workflow/campaign_manager.py` — Çok-hedefli tarama kampanya orkestrasyonu. `from_file(targets_file)` class method: dosyadan hedef listesi okur (satır başına bir hedef, yorum ve boş satır atlanır). Sequential scan: her hedef sırayla taranır. `_find_scope_file(target)` ile scope dizininden otomatik eşleme (example_com.yaml veya example.yaml). `CampaignReport` (to_markdown()) ile kampanya özet raporu. SIGINT/SIGTERM → hedefler arası graceful durdurma. CLI: `whai campaign <targets_file> [--scope-dir config/scopes] [--profile balanced]`.

**CLI Komutları:** `src/cli.py` içine iki yeni Typer komutu eklendi: `monitor` (ContinuousMonitor sarmalayıcı, interval/max_iterations/scope/profile parametreleri) ve `campaign` (CampaignManager sarmalayıcı, targets_file/scope_dir parametreleri, Rich Panel ile hedef listesi ve tamamlanma özeti).

**Test Suite:** 65 yeni test eklendi (10 test sınıfı): TestFindingHash (8), TestCanonicalVulnType (2), TestNormaliseUrl (4), TestGlobalFindingStore (7), TestScanProfiler (8), TestAutoDraftGenerator (8), TestCampaignManager (7), TestContinuousMonitor (3), TestPipelineWiring (10), TestEdgeCases (6). **Test suite: 651 → 716 tests, 0 failures.**

### v2.8.0 Güçlendirmeleri (Scan Quality & Reliability — NEXT_LEVEL_PLAN_V16)

**Phase 0 — Scan-Breaking Bug Fixes (6 item):**

**P0-1: Nikto ARRAY() Parser Fix:** `nikto_wrapper.py` `_parse_json_output()` artık Perl string interpolation artifact'larını (`ARRAY(0x...)`, `HASH(0x...)`) `_PERL_ARRAY_RE` ile temizliyor. JSON parse öncesinde bozuk referanslar `"[Perl-ref]"` stringine dönüştürülüyor.

**P0-2: Deep Probe WAF-Adaptive Retry:** `deep_probe.py` `_send_probes()` artık WAF block tespitinde (403/406/429 + WAF header/body pattern) adaptif retry yapıyor: `waf_strategy.generate_bypass_variants()` ile 3 payload varyantı üretip yeniden deniyor. Orijinal fonksiyon `_send_probes_inner()` olarak refactored, retry logic dış wrapper'da.

**P0-3: Finding Dedup Normalization Hardening:** `full_scan.py` Pass 2 cross-tool dedup artık URL normalizasyonu yapıyor: lowercase scheme+host, default port (80/443) stripping, sorted query params, trailing slash strip. `_VULN_SYNONYMS` 16→40+ canonical mapping'e genişletildi. `_DEFAULT_PORTS` dict eklendi.

**P0-4: SearchSploit Version Extraction Fix:** `searchsploit_wrapper.py` `_extract_version_from_title()` v2.7.6 P0-3'ten miras alınan hatalı regex düzeltildi — version string matching iyileştirildi.

**Phase 1 — Report Quality:**

**P1-1: Brain Response Metrics:** `intelligence.py` artık her `_brain_call()` dönüşünde JSON parse success/failure, response length, latency ve empty response oranını `state.metadata["brain_quality_metrics"]` altında takip ediyor.

**P1-2: Tool Timeout Calibration:** 6 araç için explicit `default_timeout` ClassVar override: nuclei=1800s, sqlmap=900s, katana=900s, gospider=600s, nmap=1200s, amass=600s. `SecurityTool.__init_subclass__()` category-based fallback korundu.

**P1-3: HUNTER Phase Budget:** Deep probe ve template generation aşamalarında toplam HUNTER mode süresi takip ediliyor, profil bazlı bütçe aşıldığında uyarı loglanıyor.

**Phase 2 — Scan Efficiency:**

**P2-1: ScanProfiler Pipeline Entegrasyonu:** `scan_profiler.py` artık per-stage context manager ile otomatik zamanlama yapıyor. `performance_report.md` rapor dizinine kaydediliyor.

**P2-2: Smart Endpoint Scoring (C2):** `_score_endpoint()` fonksiyonu eklendi — URL'leri parametre değeri, path derinliği, high-value parametre varlığı ve dinamik segment sayısına göre puanlıyor. `_HIGH_VALUE_PARAMS` 20+ parametre seti. HUNTER mode endpoint seçimi bu skorlamayı kullanıyor.

**P2-3: FP Pattern Learning with Dynamic Confidence (C3):** `knowledge_base.py` `save_fp_pattern()` artık `times_seen` sayacı tutuyor ve `confidence = min(0.95, 0.5 + times_seen * 0.1)` formülü ile dinamik güven skoru hesaplıyor.

**Phase 3 — FP Engine Hardening:**

**P3-1: SPA Catch-All FP Expansion:** `fp_detector.py` Layer 1b SPA penalty artık 18 vuln type'ı kapsıyor (eski 9'dan genişletildi): `sensitive_url`, `exposed_panel`, `exposed_config`, `debug_endpoint`, `source_code_disclosure`, `git_exposure`, `svn_exposure`, `env_file`, `phpinfo`, `server_status` eklendi. Title keyword'leri 5→16'ya genişletildi.

**P3-2: Known FP Pattern Additions:** `known_fps.py` FP-SPA-001 (nikto path finding on SPA-style host) ve FP-SPA-002 (file/path discovery without content verification) pattern'ları eklendi. Her ikisi de -15 penalty.

**Phase 4 — Tool Reliability:**

**P4-1: OOM Protection for Heavy Tools:** `SecurityTool` base class'a `memory_limit: int = 2 * 1024 * 1024 * 1024` ClassVar eklendi. `_set_rlimits()` closure artık instance `memory_limit` değerini kullanıyor. Per-tool override: waybackurls=512MB, gau=512MB, nuclei=1GB.

**P4-2: Pre-Scan Tool Availability Check:** `full_scan.py` `handle_scope_analysis()` artık scan başlangıcında tüm kayıtlı araçları `is_available()` ile kontrol ediyor. Bulunamayan araçlar `state.metadata["unavailable_tools"]` listesinde saklanıyor ve WARNING ile loglanıyor.

**Phase 5 — Brain Efficiency:**

**P5-1: Brain Call Parallelization:** Zaten uygulanmış — `asyncio.gather()` + `Semaphore(6)` ile paralel brain çağrıları aktif.

**P5-2: Silent Brain Failure Logging:** `intelligence.py` `generate_creative_attack_narratives()` ve `generate_dynamic_test_cases()` artık brain unavailable olduğunda `logger.info()` ile bilgi veriyor (önceden sessizce `[]` döndürüyordu).

**P5-3: SSH Watchdog Log Noise Reduction:** `engine.py` `_tunnel_watchdog_loop()` tunnel-down ve watchdog-error mesajları `logger.warning()` → `logger.debug()` olarak düşürüldü. Tunnel flapping sırasında brain.log taşması engellendi.

**Phase 6 — Next-Level Capabilities:**

**P6-1: Scope-Aware HUNTER Templates (Bare-Path Fix):** `full_scan.py` brain endpoint scope validation artık bare path'leri (ör: `/api/redeem`) destekliyor. `startswith("/")` olan endpoint'lere otomatik olarak target'ın scheme+host'u prefix olarak ekleniyor.

**P6-4: Confidence-Based Report Sections:** `report_generator.py` `to_markdown()` artık bulguları 3 güven katmanına ayırıyor: Confirmed Findings (>80%), Likely Findings (50-80%), Needs Investigation (≤50%). Yeni `_render_finding()` static method ile her bulgu bağımsız render ediliyor. Global index counter ile katmanlar arası sıralı numaralandırma.

**Test Suite:** 24 yeni regresyon testi (10 test sınıfı): TestToolTimeoutOverrides (6), TestDedupNormalization (3), TestSPAFPPatterns (3), TestToolMemoryLimits (5), TestPreScanAvailabilityCheck (1), TestSSHWatchdogLogLevel (1), TestConfidenceReportSections (3), TestEndpointScoring (2), TestFPLearningConfidence (1). **Test suite: 771 → 795 tests, 0 failures.**

### v2.8.1 Güçlendirmeleri (Production Crash Fixes — NEXT_LEVEL_PLAN_V17)

Uber.com üretim taramasının (4s18d, 84 doğrulanmış bulgu) raporlama aşamasında çökmesinin kök-neden analizine dayalı kritik düzeltmeler:

**P0-1: ScanProfiler Serialization Fix:** `session_manager.py` `sync_from_workflow_state()` artık `workflow_metadata`'yı kör kopyalamak yerine sanitize ediyor. `to_dict()` metodu olan nesneler (ScanProfiler gibi) otomatik dict'e dönüştürülür; JSON-serialize edilemeyen nesneler `str()` ile string'e çevrilir. Checkpoint `model_dump_json()` çökmesi elimine edildi.

**P0-3: WAFResult Constructor Fix:** `deep_probe.py` satır 668'deki `WAFResult(detected=True, waf_name="unknown", confidence=0.5, details={})` çağrısı düzeltildi. WAFResult sınıfı `host` alanını zorunlu ilk pozisyonel parametre olarak alır ve `details` alanı yoktur. Düzeltme: `WAFResult(host="unknown", detected=True, waf_name="unknown", confidence=0.5)`.

**P0-6: URL List Type Guard:** `full_scan.py` HUNTER Phase C fallback'inde `f.get("url", "").startswith("http")` çağrısı, `url` alanı liste olduğunda `AttributeError` ile çöküyordu. `isinstance(f.get("url", ""), str)` tip kontrolü eklendi.

**P0-7: Per-Finding Error Handling:** `report_generator.py` `generate()` metodunun bulgu dönüştürme döngüsüne try/except eklendi. Tek bir bozuk bulgu artık tüm rapor üretimini çökertmiyor; hatalı bulgular uyarı ile atlanıyor.

**P0-8: Early Findings Persistence:** `full_scan.py` `handle_reporting()` artık `findings.json`'ı rapor üretiminden ÖNCE kaydediyor. Rapor üretimi çökse bile (ReportFinding validation hatası gibi) bulgular asla kaybolmuyor.

**P0-9: tech_cve_checker Split Guard:** `tech_cve_checker.py` satır 215'teki `.strip().split()[0]` çağrısı, yalnızca boşluk içeren string'lerde `IndexError` ile çöküyordu. Ara değişkene ayrılarak boş string kontrolü eklendi.

**P1: Checkpoint & Session Save Fallback:** `session_manager.py` `checkpoint()` ve `_save_session()` metotları artık `model_dump_json()` başarısız olduğunda `json.dumps(model_dump(), default=str)` fallback serializasyonu kullanıyor. Hiçbir checkpoint daha kaybolmuyor.

**Test Suite:** 14 yeni regresyon testi (7 test sınıfı): TestMetadataSanitization (3), TestWAFResultConstructor (2), TestURLTypeGuard (2), TestReportGeneratorErrorHandling (1), TestTechCVECheckerSplitGuard (3), TestCheckpointFallback (2), TestEarlyFindingsPersistence (1). **Test suite: 850 → 864 tests, 0 failures.**

### v2.8.2 Güçlendirmeleri (URL-as-List Cascade Bug Fixes — NEXT_LEVEL_PLAN_V18)

Uber.com üretim taramasının (4s18d, 93 doğrulanmış bulgu) vulnerability_scanning, fp_elimination ve reporting aşamalarında peş peşe çökmesinin kök-neden analizine dayalı kritik düzeltmeler. Tüm hatalar tek bir kök nedenden kaynaklanıyordu: Swagger/API parser'ların `url`/`endpoint` alanlarını liste olarak üretmesi.

**KÖK NEDEN ANALİZİ:** Swagger parser ve API fuzzer, endpoint URL'lerini bazen `list` (ör: `["https://api.uber.com/v1", "https://api2.uber.com/v2"]`) olarak döndürüyordu. Bu liste değerleri Finding nesnelerine, oradan dict'lere, oradan dedup/FP/raporlama katmanlarına yayılarak 3 farklı aşamada çökmeye neden oluyordu: `unhashable type: 'list'` (dedup set'e eklenemiyor), `'list' object has no attribute 'strip'` (URL normalization), `ReportFinding.endpoint` Pydantic validation hatası.

**FIX KATMANLARI (Defense-in-Depth):**

**Layer 1 — Finding Model Validator (P0-A):** `src/tools/base.py` Finding sınıfına `@field_validator("endpoint", "target", mode="before")` eklendi. Liste girişleri ilk elemana, None boş string'e, non-string `str()` ile string'e dönüştürülüyor.

**Layer 2 — _finding_to_dict Coercion (P0-B):** `full_scan.py` `_finding_to_dict()` artık `url` değişkenini set etmeden önce liste kontrolü yapıyor. `isinstance(url, list)` ilk eleman seçilir, `not isinstance(url, str)` `str()` ile dönüştürülür.

**Layer 3 — Dedup Key Safety (P0-C):** `full_scan.py` vulnerability_scan dedup loop'u artık `f.get("url", "")` değerini dedup_key oluşturmadan önce liste string dönüşümüne tabi tutuyor. `unhashable type: 'list'` hatası tamamen elimine edildi.

**Layer 4 — FP Elimination Boundary Normalization (P0-D):** `handle_fp_elimination()` başlangıcında tüm `raw_findings` dict'leri taranarak `url`, `endpoint`, `target` alanlarındaki liste değerleri string'e dönüştürülüyor.

**Layer 5 — Reporting Boundary Normalization (P0-E):** `handle_reporting()` başlangıcında aynı normalizasyon uygulanarak ReportFinding Pydantic validation hatası engelleniyor.

**Layer 6 — URL Helper Function Safety (P0-F):** `_normalize_url()`, `_url_path()` ve `_extract_path_key()` fonksiyonları artık `Any` tipinde giriş kabul ediyor ve liste string dönüşümü yapıyor.

**P0-G: remediation.py Logger Import Fix:** `src/reporting/remediation.py` `logger` import'u eksikti — `get_remediation()` bilinmeyen vuln type ile çağrıldığında `NameError: name 'logger' is not defined` hatası fırlatıyordu. `from loguru import logger` eklendi.

**Test Suite:** 20 yeni regresyon testi (8 test sınıfı): TestFindingURLFieldValidators (7), TestFindingToDictURLCoercion (2), TestDedupKeySafety (2), TestNormalizeURLListSafety (2), TestFPEliminationURLNormalization (2), TestRemediationLoggerImport (3), TestReportingURLNormalization (1), TestEndToEndSwaggerListURL (1). **Test suite: 864 → 884 tests, 0 failures.**

### v2.8.3 Güçlendirmeleri (Type Safety Hardening — NEXT_LEVEL_PLAN_V19)

Sistematik tip güvenliği denetimi sonucunda tespit edilen sessiz veri kaybı ve potansiyel çökme riskleri:

**P0-1: Safe Float Conversion (ValueError Crash Prevention):** `full_scan.py` içine `_safe_float(val, default)` yardımcı fonksiyonu eklendi. Brain/LLM kaynaklı bulgularda `confidence_score` veya `confidence` alanları non-numeric string olabilir (örn: `"high"`, `""`, `None`). 3 kritik çağrı noktası düzeltildi: (1) confidence→severity calibration döngüsü (satır ~5435), (2) brain hypothesis confidence (satır ~4201), (3) HUNTER Phase C PoC confidence boost (satır ~4683). `poc_confidence_boost` değeri de `_safe_float` ile sarıldı.

**P0-2: _coerce_to_str Helper:** `full_scan.py` içine `_coerce_to_str(val)` yardımcı fonksiyonu eklendi. `None` → `""`, `list` → ilk eleman, non-string → `str()`. `_finding_to_dict()` içindeki `parameter`, `payload`, `description`, `evidence` alanları bu yardımcı ile sarıldı.

**P0-3: ReportFinding Field Validators:** `report_generator.py` `ReportFinding(BaseModel)` modeline 2 yeni validator eklendi: (1) `_coerce_str_fields`: 11 alan (`endpoint`, `target`, `parameter`, `payload`, `http_request`, `http_response`, `poc_code`, `summary`, `description`, `impact`, `remediation`) için list/None/non-string → string dönüşümü. (2) `_coerce_confidence`: `confidence_score` alanı için safe float dönüşümü. Böylece Finding modeli (base.py) ve ReportFinding modeli (report_generator.py) arasında savunma derinliği sağlandı.

**P0-4: ReportFinding URL Coercion in _convert_finding():** `report_generator.py` `_convert_finding()` içinde `endpoint_val` artık ReportFinding oluşturulmadan önce açıkça list→string dönüşümüne tabi tutuluyor. Böylece Pydantic validator'a ek olarak çağrı noktasında da koruma sağlanıyor.

**P0-5: Tool Availability Check Logging:** `full_scan.py` satır ~100'deki `except Exception:` bare handler'ı artık exception değişkenini yakalıyor (`_tool_avail_err`) ve `logger.debug()` ile loglıyor. P5-1 sessiz exception eliminasyonu hedefine uyum.

**Test Suite:** 43 yeni regresyon testi (8 test sınıfı): TestSafeFloat (9), TestCoerceToStr (7), TestFindingToDictFieldCoercion (4), TestReportFindingFieldValidators (13), TestReportFindingConfidenceValidator (6), TestConfidenceSeverityCalibration (1), TestEndToEndReportFinding (1), TestToolAvailabilityLogging (1). Toplam: 4 üretim kodu dosyası değiştirildi, 2 yeni yardımcı fonksiyon, 2 yeni Pydantic validator. **Test suite: 884 → 927 tests, 0 failures.**

### v2.8.4 Güçlendirmeleri (Serialization Safety & Pipeline Robustness — NEXT_LEVEL_PLAN_V20)

Uber.com üretim taramasının (4s18d) checkpoint serialization hatalarının ve orchestrator error-path veri kaybının kök-neden analizine dayalı kritik düzeltmeler:

**KÖK NEDEN ANALİZİ:** `state.metadata` dict'inde saklanan `WAFResult` dataclass nesnesi `to_dict()` metoduna sahip olmadığından, `sync_from_workflow_state()` tarafından `str()` ile garbage string'e dönüştürülüyordu. Bu durum: (1) checkpoint'lerde WAF verisi kaybı, (2) resume sonrası `AttributeError: 'str' object has no attribute 'detected'` crash riski, (3) WAF-adaptive nuclei rate ayarının resume sonrası devre dışı kalması. Ayrıca orchestrator'daki checkpoint retry path'inde sync başarısız olduğunda retry sadece checkpoint'i tekrar deniyordu (sync'siz), ve stage failure/timeout durumlarında hiç checkpoint kaydedilmiyordu.

**P0-1: WAFResult/WAFStrategy to_dict() + from_dict():** `src/tools/scanners/waf_strategy.py` — Her iki dataclass'a `to_dict()` ve `from_dict()` metotları eklendi. `to_dict()` JSON-serializable dict döner (nested WAFStrategy dahil). `from_dict()` checkpoint resume için dict'ten yeniden oluşturma sağlar. `sync_from_workflow_state()` artık `hasattr(_mv, "to_dict")` kontrolü ile WAFResult'ı doğru şekilde dict'e çevirir (str()'e dönüşüm yerine).

**P0-2: Orchestrator Checkpoint Retry Path Fix:** `src/workflow/orchestrator.py` — Checkpoint retry bloğu artık sadece `checkpoint()` değil, `sync_from_workflow_state()` + `checkpoint()` birlikte retry ediyor. Böylece sync başarısız olduğunda retry path stale/unsanitized session verisiyle checkpoint kaydetmiyor.

**P0-3: Stage Failure/Timeout Checkpoint:** `src/workflow/orchestrator.py` — Stage error/timeout handler artık `record_stage_error()` sonrasında `sync_from_workflow_state()` + `checkpoint(force=True)` çağırıyor. FP elimination timeout'unda promote edilen unprocessed bulgular, vulnerability scan partial sonuçları ve diğer kısmi çalışma artık disk'e persiste ediliyor. `force=True` checkpoint throttle'ı bypass eder.

**P0-4: Safe WAFResult Consumer Helper:** `src/workflow/pipelines/full_scan.py` — `_get_waf_result(state)` helper fonksiyonu eklendi. Resume sonrası `state.metadata["waf_result"]` değeri WAFResult nesnesi, dict (to_dict'ten) veya string (eski fallback) olabilir. Helper her üç formayı da güvenli şekilde handle eder: WAFResult direkt döner, dict `WAFResult.from_dict()` ile reconstruct edilir, string/None durumunda `None` döner. Nuclei rate adjustment consumer bu helper'ı kullanacak şekilde güncellendi.

**Test Suite:** 29 yeni regresyon testi (7 test sınıfı): TestWAFStrategyToDict (5), TestWAFResultToDict (8), TestGetWAFResult (6), TestSyncMetadataWAFResult (2), TestOrchestratorCheckpointRetry (2), TestStageFailureCheckpoint (2), TestMetadataSerializationEdgeCases (4). Toplam: 3 üretim kodu dosyası değiştirildi, 2 yeni to_dict()/from_dict() metot çifti, 1 yeni helper fonksiyon, 2 orchestrator error-path düzeltmesi. **Test suite: 927 → 986 tests, 0 failures.**

### v2.8.5 Güçlendirmeleri (Production Quality & Tool Reliability — NEXT_LEVEL_PLAN_V21)

Uber.com üretim taramasının (4 saat+, 93 doğrulanmış bulgu) WARNING/ERROR log analizine dayalı araç güvenilirliği ve pipeline sağlamlığı iyileştirmeleri:

**P0-1: _dict_to_finding Validation Fix:** `full_scan.py` `_dict_to_finding()` tamamen yeniden yazıldı. Tüm string alanları (`parameter`, `payload`, `description`, `evidence`, `cve_id`, `cwe_id` vb.) `_coerce_to_str()` ile sarıldı — Swagger/API parser kaynaklı list değerler ve None'lar güvenle string'e dönüştürülüyor. Tüm numeric alanlar (`confidence`, `cvss_score`) `_safe_float()` ile sarıldı — LLM kaynaklı "high"/"None"/"" gibi non-numeric string'ler default değere fallback ediyor. `_coerce_to_str()` nested list desteği eklendi (2 seviye recurse).

**P0-2: Brain Timeout Floor Proportional Minimum:** `_brain_enhanced_options()` timeout floor'u sabit `30s` yerine `max(30, base_timeout * 0.5)` oransal minimum kullanıyor. Brain'in dalfox timeout'unu 180s (BALANCED) → 30s'ye düşürmesi engellendi; yeni minimum 90s. STEALTH XSS (300s base) için floor 150s.

**P0-3: Go Tool Memory Limits:** `gau_wrapper.py` ve `waybackurls_wrapper.py` `run()` metotlarına `GOMEMLIMIT=512MiB` ve `GOGC=50` env değişkenleri eklendi. Go runtime'ın sınırsız bellek tahsisinden kaynaklanan "failed to reserve page summary memory" OOM crash'leri engellendi.

**P1-1: Nuclei Thread Exhaustion Prevention:** `nuclei_wrapper.py` içine `_go_env()` helper metodu eklendi: `GOMAXPROCS=4` + `GOMEMLIMIT`; hem `run()` hem `run_batch()` bu env'i kullanıyor. Pipeline nuclei semaphore'u 3→2'ye düşürüldü. "runtime/cgo: pthread_create failed: Resource temporarily unavailable" crash'i engellendi.

**P1-2: http2_http3_checker SSL Noise Reduction:** `APPLICATION_DATA_AFTER_CLOSE_NOTIFY` TLS hatası `logger.warning` → `logger.debug` olarak düşürüldü. Tarama başına 9+ gereksiz WARNING loglanması engellendi.

**P1-3: Nuclei Template YAML Sanitization:** `nuclei_template_writer.py` içine `_sanitize_llm_yaml()` fonksiyonu eklendi. LLM'in ürettiği YAML'daki 3 yaygın hata otomatik düzeltiliyor: (1) tab→2 space dönüşümü, (2) unbalanced double-quoted scalar'larda single-quote'a geçiş, (3) list item'larda internal double-quote düzeltme. Hem `generate_nuclei_template()` hem `_fix_template_with_llm()` çıktısına uygulanıyor. "while scanning a double-quoted scalar" YAML hataları azaltıldı.

**P2-1: Report save_markdown/save_json Safety:** `report_generator.py` `save_markdown()` ve `save_json()` metotları try/except ile sarıldı. `to_markdown()` çöktüğünde emergency fallback içerik yazılıyor. `to_json()` çöktüğünde yol yine döndürülüyor. Rapor üretim hatası artık tüm taramayı çökertmiyor.

**Test Suite:** 39 yeni regresyon testi (8 test sınıfı): TestDictToFindingCoercion (12), TestBrainTimeoutFloor (4), TestGoToolMemoryLimits (4), TestNucleiThreadExhaustion (3), TestHTTP2CheckerLogLevel (1), TestSanitizeLlmYaml (7), TestReportSaveSafety (3), TestEdgeCases (5). **Test suite: 986 → 995 tests, 0 failures.**

### v2.8.6 Güçlendirmeleri (Deep Type Safety Audit & Crash Prevention — NEXT_LEVEL_PLAN_V22)

Kod tabanı genelinde sistematik tip güvenliği denetimi. İki paralel derin-arama audit'i (crash risk patterns + dead module analizi) sonucunda 14 dosyada ~30+ çökme noktası düzeltildi:

**P0-1: ExploitVerifier Type Safety (5 CRITICAL):** `src/tools/exploit/exploit_verifier.py` içine `_safe_float()` ve `_coerce_url()` modül-düzeyi yardımcılar eklendi. `_prioritize_candidates()`: URL-as-list filtre (`startswith("http")` listeye çağrılması), confidence>=40.0 karşılaştırmasında string "high" crash, sort key'de float cast. `_verify_with_poc()` ve `_verify_with_curl()`: bare `float()` cast → `_safe_float()`. `_verify_with_nuclei()`: URL coercion. Batch exception handler: bare confidence erişimi → `_safe_float()`, `logger.debug` → `logger.warning`.

**P0-2: Screenshot URL Type Check:** `full_scan.py` screenshot capture bölümünde `isinstance(f.get("url", ""), str)` tip kontrolü eklendi — URL liste olduğunda `AttributeError` engellendi.

**P0-3: AutoDraft Type Safety (3 HIGH):** `src/reporting/auto_draft.py` içine `_safe_float()` ve `_coerce_str()` yardımcılar eklendi. `should_draft()`: severity `.strip()` potansiyel liste üzerinde → `_coerce_str()`, confidence `float()` → `_safe_float()`. `generate_draft()`: tüm alan erişimleri `_coerce_str()` ile sarıldı, cvss_score `float()` → `_safe_float()`.

**P0-4: ResultAggregator String Coercion:** `src/workflow/result_aggregator.py` `_fingerprint()` static metoduna inline `_s()` yardımcısı eklendi. 5 alan (vuln_type, target, endpoint/url, parameter, method) üzerindeki `.lower().strip()` çağrıları artık list/None değerleri güvenle string'e dönüştürüyor.

**P1-1: Intelligence/Reflection/Adaptive Float Safety:** `intelligence.py` `_parse_verification_result_from_dict()` inline `_sf()` helper ile yeniden yazıldı — `confidence` ve `cvss_override` alanlarında non-numeric LLM çıktıları güvenle handle ediliyor. `self_reflection.py`: Critique score oluşturmada `_sf()` helper eklendi. `adaptive_strategy.py`: SUBDOMAIN_FOUND ve ENDPOINT_FOUND sinyal işleyicilerinde `int()` cast try/except ile sarıldı — non-integer count fallback +=1.

**P1-2: OSINT Wrapper resp.json() Safety:** `shodan_wrapper.py`: DNS resolve ve host detail resp.json() çağrıları try/except ile sarıldı → non-JSON (rate limit HTML sayfaları) durumunda `ToolResult(success=False)` dönüyor. `censys_wrapper.py`: 4 resp.json() çağrısı (host resolve, host detail, search, certificate) sarıldı. `zaproxy_wrapper.py`: `_api_get()` ve `_api_post()` resp.json() çağrıları sarıldı → non-JSON durumunda boş dict `{}` dönüyor + `logger.warning`.

**P2-1: Silent Exception Visibility (8 blok):** `knowledge_base.py`: FP pattern deserialization `except Exception: pass` → `logger.warning()`. `engine.py`: Brain retry exhaustion exception artık gerçek hatayı logluyor. `full_scan.py`: PoC execution silent exception → `logger.warning()`. `session_manager.py`: Session iteration `except Exception: continue` → `logger.debug()`. `report_generator.py`: Clustering ve emergency fallback `except Exception: pass` → `logger.debug()`/`logger.warning()`.

**Test Suite:** 68 yeni regresyon testi (16 test sınıfı): TestExploitVerifierSafeFloat (8), TestExploitVerifierCoerceUrl (5), TestExploitVerifierPrioritizeCandidates (5), TestExploitVerifierBatchFallback (1), TestAutoDraftSafeFloat (4), TestAutoDraftCoerceStr (5), TestAutoDraftShouldDraft (5), TestAutoDraftGenerateDraft (2), TestResultAggregatorFingerprint (6), TestIntelligenceVerificationParsing (9), TestSelfReflectionScoreSafety (1), TestAdaptiveStrategyIntFallback (3), TestShodanJsonSafety (3), TestCensysJsonSafety (2), TestZAProxyJsonSafety (2), TestSilentExceptionVisibility (3), TestEdgeCases (4). **Test suite: 995 → 1063 tests, 0 failures.**

### v2.8.7 Güçlendirmeleri (Dead Module Wiring & Pipeline Integration — NEXT_LEVEL_PLAN_V23)

İki paralel derin-arama audit'i (~6.600 satır ölü kod tespiti + pipeline wiring boşlukları analizi) sonucunda 4 üretim dosyasında 6 kritik pipeline entegrasyonu gerçekleştirildi:

**P0-1: 14 Unregistered SecurityTool Subclass Wiring:** `src/tools/register_tools.py` — 14 previously-dead SecurityTool alt sınıfı kayıt altına alındı: CSPSubdomainDiscovery, SourceMapExtractor, VHostFuzzer, CDNDetector, FaviconHasher, EmailSecurityChecker, ReverseIPLookup, GitHubSecretScanner, CloudStorageEnumerator, MetadataExtractor, MassAssignmentChecker, DeserializationChecker, BFLABOLAChecker, FourXXBypassChecker. Her biri `try/except ImportError` pattern ile güvenli import. Bu araçlar artık `ToolRegistry.get_all_tools()`, dry-run, benchmark ve telemetri tarafından görünür.

**P0-2: GF Router Task Detail Storage:** `full_scan.py` — GF auto-router sonuçları artık yalnızca sayı (`gf_routed_tasks`) değil, tam görev detayları (`gf_routed_tasks_detail`) ile metadata'ya kaydediliyor: her görev için tool, urls[:30], category, priority bilgileri. Downstream telemetri ve agentic karar bağlamı zenginleştirildi.

**P0-3: DecisionEngine Full Wiring:** `full_scan.py` — `DecisionEngine` artık sadece `profile=` değil, `brain_engine=`, `knowledge_base=` ve `registry=` parametreleri ile tam donanımlı oluşturuluyor. `getattr(state, "brain_engine", None)` ve `getattr(_de_intel, "knowledge_base", None)` ile güvenli erişim. Brain-powered araç seçimi ve teknoloji-farkında filtreleme artık tam kapasitede.

**P0-4: SSRFMap Pipeline Integration:** `full_scan.py` — ssrfmap, vulnerability scan pipeline'ına bağlandı (XSS/dalfox bloğundan sonra, CORS'tan önce). İki kaynaklı akıllı URL seçimi: (1) GF-sınıflandırılmış SSRF URL'leri, (2) SSRF-göstergesi parametre isimlerini (`url`, `uri`, `path`, `dest`, `redirect`, `src`, `proxy`, `link`, `fetch`, `target`) içeren URL'ler. Semaphore(2), max 15 URL, 120s timeout, auth header passthrough. `_tool_to_vuln` mapping ve agentic remaining tools güncellendi.

**P1-1: Dynamic Wordlist Post-Enumeration Consumer:** `full_scan.py` — Dinamik kelime listesi artık aktif olarak tüketiliyor. Enumeration aşamasının sonunda, `state.metadata["dynamic_wordlist_path"]` dosyası mevcutsa ve >50 byte ise, ffuf ile en fazla 3 canlı host üzerinde hedefli fuzzing çalıştırılıyor. Semaphore(2), 180s timeout. Bulunan yeni endpoint'ler `collected["endpoints"]` listesine ekleniyor.

**P1-2: BayesianFilter FP Layer Integration:** `src/fp_engine/fp_detector.py` — Bayesian olasılık filtresi FP analiz pipeline'ına "Layer 8" olarak entegre edildi. ConfidenceScorer hesaplamasından sonra ve ağırlıklı birleştirmeden önce çalışır. Mevcut katman sonuçlarından (multi_tool_agree, payload_reflected_unencoded, waf_block, oob_callback, response_anomaly) evidence dict'i oluşturur. `BayesianFilter.evaluate()` ile posterior olasılığı hesaplar. En az 2 sinyal kullanıldığında ±8 sınırlı delta olarak layer_score'a uygulanır. Evidence chain'e log kaydı eklenir.

**Test Suite:** 64 yeni regresyon testi (10 test sınıfı): TestNewToolRegistrations (14), TestToolImportability (14), TestGFRouterDetailStorage (2), TestDecisionEngineWiring (5), TestSSRFMapPipelineIntegration (4), TestDynamicWordlistConsumer (3), TestBayesianFilterIntegration (3), TestBayesianFilterUnit (9), TestBayesianDeltaComputation (5), TestEdgeCases (6). **Test suite: 1063 → 1127 tests, 0 failures.**

### v2.8.8 Güçlendirmeleri (FP Engine Deep Wiring & Brain Module Integration — NEXT_LEVEL_PLAN_V24)

FP Engine'deki 7 ölü modülün sistematik pipeline entegrasyonu. Daha önce yazılmış ama hiçbir zaman çağrılmayan doğrulama, puanlama ve geri bildirim modülleri FP analiz pipeline'ına bağlandı:

**P1: ToolQuirkChecker as Layer 1c:** `src/fp_engine/fp_detector.py` — Araç-spesifik FP kalıp veritabanı (sqlmap boolean-blind, nikto OSVDB, nmap version guess, wpscan version mismatch, ffuf size-only, vb.) FP analizine "Layer 1c" olarak eklendi. `ToolQuirkChecker.check()` araç adı ve bulgu dict'i ile çağrılır, `total_modifier` [-30, +10] aralığında sınırlandırılır. Her araç için bilinen quirk'ler otomatik uygulanır.

**P2: WafArtifactDetector Enhancement for Layer 5:** `src/fp_engine/fp_detector.py` — Eski basit WAF header kontrolü `WafArtifactDetector.analyze()` ile değiştirildi. 8+ WAF imzası (Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5, Sucuri, Wordfence), block page tespiti, CDN algılama ve cookie analizi dahil derin WAF analizi. WAF penalty [-30, 0] aralığında sınırlandırılır.

**P3: ContextVerifier as Layer 2c:** `src/fp_engine/fp_detector.py` — HTTP bağlam doğrulaması "Layer 2c" olarak eklendi. `ContextVerifier.verify()` bulgu dict'indeki `http_request`/`http_response` alanlarından `HttpContext` oluşturur, WAF müdahalesi, payload reflection, status code anomalisi, timing analizi yapar. Sonuç `confidence_delta` [-15, +10] aralığında sınırlandırılır.

**P4: ResponseDiffAnalyzer Integration in Layer 6:** `src/fp_engine/fp_detector.py` — Layer 6 `_layer6_rerequest_verify()` içine derin diferansiyel analiz eklendi. `ResponseDiffAnalyzer.analyze()` normal response ile payload response'u karşılaştırır: body hash diff, payload reflection/encoding tespiti, status code farkı, zamanlama anomalisi, vuln-spesifik kontroller (SQL error mesajları, XSS context, command output). `is_significant` ise `confidence_delta` FP skoruna eklenir.

**P5: FPFeedbackManager Pipeline Wiring + Layer 0:** İki entegrasyon noktası: (1) `src/fp_engine/fp_detector.py` Layer 0 — FP analizinin en başında `FPFeedbackManager.get_confidence_adjustment(tool, vuln_type)` çağrılarak araç+vuln kombinasyonunun tarihsel FP oranına göre [-15, +5] aralığında ön-ayarlama yapılır. (2) `src/workflow/pipelines/full_scan.py` `handle_fp_elimination()` — FP analizi sonrasında tüm bulgular `FPFeedbackRecord` olarak `record_batch()` ile SQLite veritabanına kaydedilir. Sonraki taramalarda öğrenilmiş FP paternleri kullanılır.

**P6: RiskAssessor Wiring in handle_reporting:** `src/workflow/pipelines/full_scan.py` `handle_reporting()` — Rapor üretiminden önce `RiskAssessor.prioritise_findings()` çağrılarak bulgular risk skoru, exploit zorluğu, etki puanı ve güven skoruna göre sıralanır. `RiskAssessment` nesnelerinden `risk_score` ve `priority_rank` finding metadata'sına eklenir.

**P7: ManualVerifyGuideGenerator in auto_draft.py:** `src/reporting/auto_draft.py` `generate_draft()` — Güven skoru 30-75 aralığında olan (orta güven) bulgular için otomatik manuel doğrulama rehberi oluşturulur. `ManualVerifyGuideGenerator.generate()` vuln türüne göre adım adım doğrulama talimatları üretir, `generate_markdown()` ile markdown'a çevrilir ve taslak raporun sonuna eklenir.

**Test Suite:** 72 yeni regresyon testi (11 test sınıfı): TestToolQuirkChecker (20 — 10 parametrized), TestWafArtifactDetector (7), TestContextVerifier (4), TestResponseDiffAnalyzer (7), TestFPFeedbackManager (6), TestRiskAssessor (6), TestManualVerifyGuideGenerator (6), TestFPDetectorLayerWiring (5), TestPipelineWiring (2), TestAutoDraftWiring (2), TestEdgeCases (6). **Test suite: 1127 → 1199 tests, 0 failures.**

### v3.0 Coverage Hardening (Wave 2 — Post-Revolution Audit)

Devrim fazları tamamlandıktan sonra yapılan derin audit sonucunda kalan response-validation kör noktaları kapatıldı. Amaç: araçların ürettiği ham “hit”leri doğrudan güvenmek yerine, redirect/WAF/SPA/error response kalıplarını mümkün olduğunca kaynakta elemek.

**Phase 6 — Deep Probe Hardening:** `src/workflow/pipelines/deep_probe.py` artık `ResponseValidator` ile baseline ve probe response'larını doğruluyor. WAF/CDN/SPA catch-all response'lar `_detect_indicators()` aşamasına geçmeden eleniyor. `deep_probe_batch()` yeni `host_profiles` parametresi ile `cdn_only`, `redirect_host` ve `static_site` host tiplerini tamamen skip ediyor.

**Phase 7 — Critical Checker Fixes:** 6 yüksek-risk checker düzeltildi.
- `auth_bypass.py` artık 301/302 redirect'leri bypass başarısı saymıyor; 200 dönen WAF/challenge body'lerini de reddediyor.
- `info_disclosure_checker.py` yalnızca gerçek `200 OK` içerikleri kabul ediyor; `curl -L` sonrası ara redirect status'lerinden etkilenmemek için son status satırı kullanılıyor.
- `http_method_checker.py` TRACE için body echo doğrulaması yapıyor; PUT için follow-up GET ile dosya oluşumu doğrulanmadan finding üretilmiyor.
- `bfla_bola_checker.py` 200/201/204 dönse bile gövdede `unauthorized`, `forbidden`, `denied`, `method not allowed` gibi hata imzaları varsa bulgu üretmiyor.
- `cache_poisoning_checker.py` canary reflection olsa bile Cloudflare/Sucuri/Akamai tarzı challenge body'lerinden finding üretmiyor.
- `header_checker.py` artık status code'u da parse ediyor; missing-header bulguları yalnızca 2xx response'lar için oluşturuluyor.

**Phase 8 — Nuclei Post-Scan Validation:** `src/tools/scanners/nuclei_wrapper.py` parsed JSONL sonuçlarını artık körlemesine finding'e çevirmiyor. `response` alanındaki raw HTTP metadata parse edilerek `ResponseValidator` üzerinden redirect, WAF block page ve generic 5xx error page filtreleniyor. Yumuşak WAF/CDN sinyalleri (ör. `CF-Ray` header'ı ile 200 response) finding'i tamamen silmek yerine confidence'ı düşürüyor. Bu katman özellikle include-rr açıkken ham matcher hit'lerinin gerçek uygulama cevabı mı yoksa edge/WAF cevabı mı olduğunu ayırmak için eklendi.

**Phase 9 — Final Regression Verification:** Yeni regression paketleri eklendi: `tests/test_tools/test_coverage_hardening_phase7.py` (45 test) ve `tests/test_tools/test_nuclei_post_validation_phase8.py` (6 test). Tam test suite son durum: **1717 passed, 2 skipped**.

### v3.1 Quality Hardening (Wave 3 — Phase 10 Batch 1)

Wave 3'ün ilk uygulama diliminde, hâlâ `status==200` veya kaba body-length farkını zafiyet kanıtı sayan yüksek-FP üreten checker'lar sertleştirildi. Amaç: 200/403/429 yanıtlarını körlemesine güvenmek yerine, gerçek uygulama içeriği ile WAF/login/error/challenge body'lerini ayırmak.

**RateLimitChecker Hardening:** `src/tools/scanners/custom_checks/rate_limit_checker.py` artık başarılı istekleri yalnızca `ResponseValidator`'dan geçen ve WAF/challenge imzası taşımayan yanıtlar için sayıyor. `302` artık başarı kabul edilmiyor; Cloudflare/Akamai/Sucuri tarzı body'ler ve yüksek hata oranı görüldüğünde bulgu üretilmiyor. IP-header bypass testi de aynı meaningful-success mantığını kullanıyor.

**FourXXBypass Response Validation:** `src/tools/scanners/custom_checks/fourxx_bypass.py` artık baseline blocked response body'sini saklıyor ve bypass denemesinde dönen `200` cevabı `ResponseValidator` ile doğruluyor. Ayrıca login/error/WAF body'leri (`login`, `sign in`, `access denied`, `captcha`, `cloudflare`, vb.) eleniyor; finding oluşturmak için body'nin gerçek kaynak işareti (`dashboard`, `admin`, `settings`, path token'ları) taşıması gerekiyor.

**GraphQL Deep Scanner Validation Layer:** `src/tools/scanners/custom_checks/graphql_deep_scanner.py` içine `_validated_graphql_response()` yardımcı katmanı eklendi. Tüm kritik `status_code == 200` yolları artık bu katmandan geçiyor: batched query, depth-limit, directive abuse, alias overloading, mutation IDOR, introspection bypass, field bruteforce, mutation discovery ve APQ testleri. HTML/WAF challenge sayfaları, auth error JSON'ları (`unauthorized`, `forbidden`, `permission denied`) ve parse edilemeyen response'lar finding'e dönüşmüyor. Ayrıca depth/directive DoS testleri sabit eşik yerine baseline'ın 3 katı gecikme ile değerlendiriliyor.

**Wave 3 Regression Tests:** `tests/test_tools/test_wave3_checker_hardening.py` ile 14 yeni test eklendi. Kapsam: rate-limit meaningful success + WAF rejection, fourxx bypass login/error body rejection, GraphQL validated response helper, batch query auth-error rejection ve baseline-multiplier korumaları. **Test suite: 1717 → 1731 tests, 0 failures, 2 skipped.**

### v3.2 Quality Hardening (Wave 3 — Phase 10 Batch 2-3 + Phase 11-13)

Wave 3'ün ikinci yarısı: kalan checker sertleştirmeleri, wrapper güven kalibrasyonu, ölü modül bağlantısı ve analiz modülü test kapsamı genişletmesi.

**Phase 10 Batch 2 — 5 Checker WAF/SPA Hardening:**

**JWT Checker WAF Guard:** `src/tools/scanners/custom_checks/jwt_checker.py` artık tüm test fonksiyonlarında (`_test_none_algorithm`, `_test_weak_secret`, `_test_expired_token`, `_test_kid_injection`, `_test_signature_stripping`, `_test_claim_tampering`) `ResponseValidator` ile yanıt doğrulaması yapıyor. WAF block page, login redirect ve error page dönen yanıtlar bulgu üretmiyor.

**API Endpoint Tester Validation:** `src/tools/scanners/custom_checks/api_endpoint_tester.py` artık `_check_endpoint()` ve `_check_auth_bypass()` akışlarında `ResponseValidator` kullanıyor. WAF challenge sayfaları ve auth error JSON'ları (`unauthorized`, `forbidden`, `denied`) endpoint'i erişilebilir saymıyor.

**Business Logic Checker Guard:** `src/tools/scanners/custom_checks/business_logic.py` artık `_check_price_manipulation()` ve `_check_quantity_manipulation()` akışlarında `ResponseValidator` ile doğrulama yapıyor. WAF/SPA catch-all response'lar sunucu tarafı doğrulama hatası olarak sayılmıyor.

**Race Condition Checker Validation:** `src/tools/scanners/custom_checks/race_condition.py` artık `_test_race_condition()` akışında `ResponseValidator` ile yanıtları doğruluyor. WAF rate-limit response'ları (429 + challenge body) race condition başarısı olarak sayılmıyor.

**IDOR Checker Response Validation:** `src/tools/scanners/custom_checks/idor_checker.py` artık `_test_idor()` akışında `ResponseValidator` kullanıyor. Farklı kullanıcı bağlamında dönen WAF/login/error body'leri IDOR başarısı olarak sayılmıyor.

**Phase 10 Batch 2 Tests:** `tests/test_tools/test_wave3_checker_hardening.py` içine 26 yeni test eklendi (toplam 40). **Test suite: 1731 → 1757 tests, 0 failures, 2 skipped.**

**Phase 10 Batch 3 — 2 Remaining Checker WAF/Response Hardening:**

**Prototype Pollution Checker Hardening:** `src/tools/scanners/custom_checks/prototype_pollution_checker.py` artık tüm 3 test fazında (query params, JSON body, form params) `ResponseValidator` ile yanıt doğrulaması yapıyor. Baseline request WAF/error page döndürüyorsa URL tamamen atlanıyor. Status 510 (pollution-specific) tespiti WAF kontrolünden muaf tutuluyor. Canary reflection kontrolü artık WAF body rejection içeriyor.

**WebSocket Checker Response Validation:** `src/tools/scanners/custom_checks/websocket_checker.py` artık 101 upgrade response'larını gerçek WebSocket header'ları (`Upgrade: websocket` veya `Sec-WebSocket-Accept`) ile doğruluyor. Discovery ve CSWSH akışlarında WAF body rejection eklendi. Non-real-101 CSWSH bulguları düşürülmüş confidence (55.0) ile raporlanıyor.

**Phase 10 Batch 3 Tests:** `tests/test_tools/test_wave3_checker_hardening.py` içine 22 yeni test eklendi (toplam 62). **Test suite: 1840 → 1862 tests, 0 failures, 2 skipped.**

**Phase 11 — Pipeline Filter + Wrapper Confidence Calibration:**

**ResponseValidator Pipeline Filter:** `src/workflow/pipelines/full_scan.py` `handle_vulnerability_scan()` artık Nuclei, Nikto ve diğer araç bulgularını topladıktan hemen sonra ResponseValidator ile toplu filtreleme yapıyor. WAF block page, generic error page ve login redirect döndüren raw finding'ler pipeline seviyesinde eleniyor (vs. checker seviyesinde tek tek).

**7 Wrapper Confidence Calibration:** 7 scanner wrapper'ın confidence hesaplamaları kalibre edildi — araçların doğrulamadan ürettiği ham bulgulara aşırı güven atanması engellendi:
- `dalfox_wrapper.py`: Base confidence 75→60, verified→80, reflected→50
- `sqlmap_wrapper.py`: Base confidence 80→65, confirmed→85, blind→55
- `commix_wrapper.py`: Base confidence 75→60, confirmed→80, blind→50
- `tplmap_wrapper.py`: Base confidence 75→55, confirmed→80, detected→45
- `crlfuzz_wrapper.py`: Base confidence 70→50, header-injected→65
- `nikto_wrapper.py`: Base confidence 65→45, OSVDB→35
- `corsy_wrapper.py`: Base confidence 70→50, with-ACAC→75, no-ACAC→35

**Phase 11 Tests:** `tests/test_tools/test_wave3_wrapper_hardening.py` ile 17 yeni test eklendi. **Test suite: 1757 → 1774 tests, 0 failures, 2 skipped.**

**Phase 12 — Dead Module Wiring:**

**CSP Subdomain Discovery Pipeline Integration:** `src/workflow/pipelines/full_scan.py` enumeration aşamasına `CSPSubdomainDiscovery` bağlandı. Canlı host'ların CSP header'larından subdomain/domain çıkarımı yapılarak keşif zenginleştiriliyor.

**Phase 13 — Test Coverage Expansion:**

**4 Untested Analysis Module Coverage:** `tests/test_analysis/test_wave3_analysis_coverage.py` ile 66 yeni test eklendi (10 test sınıfı). Kapsanan modüller:
- `vulnerability_analyzer.py` (618 satır): VulnContext, ExploitFeasibility, VULN_KNOWLEDGE (13 vuln type), VulnerabilityAnalyzer mantığı (CVSS context, exploit feasibility, impact assessment, correlation, summary)
- `threat_model.py` (686 satır): ThreatModeler (STRIDE categories, threat templates, likelihood/impact estimation, port/tech threats, markdown export), ImpactAssessor (dimension scoring, narrative generation)
- `impact_assessor.py` (408 satır): ImpactCategory/ImpactLevel/DataClassification enums, ImpactReport model, VULN_IMPACT_MAP (11 vuln type), _adjust_score (internet_facing/auth/sensitive_data/waf/environment), score_to_level, urgency determination, assess_multiple
- `output_aggregator.py` (598 satır): NormalizedFinding dedup, ingest+merge, cross-tool verification, severity/vuln_type normalization, target normalization, attack chain detection, title similarity, finding priority sort, false positive marking, get_findings_for_report filter

**OutputAggregator Field Name Bug Fix:** `src/analysis/output_aggregator.py` `_normalize_finding()` artık `finding.cwe` / `finding.cve` yerine `getattr()` ile `cwe_id` / `cve_id` alanlarına güvenli erişim yapıyor. Finding model'inin alan adları (`cwe_id`, `cve_id`) ile OutputAggregator'ın beklediği adlar (`cwe`, `cve`) arasındaki uyumsuzluk düzeltildi.

**Wave 3 Final Test Count:** 66 yeni test (Phase 13) + 17 (Phase 11) + 26 (Phase 10 Batch 2) + 14 (Phase 10 Batch 1) + 22 (Phase 10 Batch 3) = **145 yeni regresyon testi**. **Test suite: 1774 → 1862 tests, 0 failures, 2 skipped.**

### v3.3 Radical Finding Quality Revolution (v5.0 — FP Rate Reduction)

Üretim taramalarında (Uber.com 93 bulgu, Shopify taraması) gözlemlenen yüksek false positive oranının sistematik kök-neden analizi sonucunda 7 fazlı kalite devrimi. Amaç: tüm pipeline katmanlarında kanıt kalitesini yükseltmek, doğrulanmamış/düşük güvenli bulguları raporlanmadan önce elemek.

**Phase 0 — Pipeline Reliability Foundation (6 item):**

**P0-1: Nuclei Confidence Modifier Integration:** `nuclei_wrapper.py` artık template'in `confidence_modifier` alanını (template metadata veya matcher info'dan) parse edip base confidence hesaplamasına katıyor. `validator_result = None` durumunda güvenli fallback.

**P0-2: FP Medium Confidence Threshold:** `src/utils/constants.py` içine `FP_MEDIUM_CONFIDENCE_THRESHOLD = 65` eklendi. FP engine artık MEDIUM+ severity bulgular için minimum 65 güven skoru gerektiriyor. Pipeline genelinde tek noktadan konfigüre edilebilir eşik.

**P0-3: SPA Baseline Capture & Severity Calibration:** `full_scan.py` artık preflight aşamasında SPA detection sonuçlarını baseline olarak saklıyor. Severity calibration 3-katmanlı: confidence<40 + severity≥MEDIUM → LOW; confidence<50 + severity≥HIGH → MEDIUM; confidence<65 + severity=CRITICAL → HIGH. Plan'daki 2-katmanlı eşikten daha konservatif.

**P0-4: Nikto Confidence Floor:** `nikto_wrapper.py` base confidence 45→30'a düşürüldü. Nikto'nun yüksek FP oranı nedeniyle tüm bulgular düşük güvenle başlıyor; kanıt kalitesine göre yükseltiliyor.

**P0-5: EvidenceQualityGate:** YENİ MODÜL `src/fp_engine/evidence_quality_gate.py`. Severity-tiered minimum kanıt gereksinimleri: CRITICAL (min_confidence=75, requires_reproduction=True, min_evidence_items=3, requires_response_diff=True), HIGH (70, True, 2, False), MEDIUM (55, False, 1, False), LOW (30, False, 0, False). `gate()` → `GateResult(passed, reason, recommendation)`. Pipeline'a entegre: raporlama öncesi son kalite kapısı.

**Phase 1 — Evidence Quality Gate + OOB Tiering (3 item):**

**P1-1: Interactsh CDN/Infrastructure IP Filtering:** `interactsh_wrapper.py` artık callback IP'lerini CDN/WAF/DNS altyapı IP'lerine karşı kontrol ediyor. `is_infrastructure_ip()` fonksiyonu `data/known_infrastructure_ips.json` dosyasından ~80 CIDR yükleyerek Cloudflare, Akamai, Fastly, AWS CloudFront, Google Cloud CDN, Azure CDN, Sucuri, Incapsula, StackPath ve DNS provider IP aralıklarını filtreler. `classify_callback_quality()` → `strong` (non-infra, unique data), `moderate` (non-infra, generic), `weak` (infra IP), `noise` (self-IP/invalid).

**P1-2: OOB Tiered Confidence Boost:** `confidence_scorer.py` OOB callback boost'u artık kalite bazlı: `strong` → +28, `moderate` → +15, `weak` → +5, `noise` → +0. Eski sabit +25 boost yerine granüler kalite değerlendirmesi.

**P1-3: FP Detector OOB Quality Routing:** `fp_detector.py` artık finding metadata'sındaki `callback_quality` alanını okuyarak OOB doğrulama skorunu kaliteye göre ağırlıklandırıyor. Strong callback'ler tam kredi, weak callback'ler minimum kredi alıyor.

**Phase 2 — Endpoint Pre-flight Validation (2 item):**

**P2-1: Pre-flight Endpoint Check:** `full_scan.py` içine `_preflight_check()` fonksiyonu eklendi. `httpx.AsyncClient` + `asyncio.Semaphore(10)` ile tüm endpoint'lere hafif HEAD/GET kontrolü. WAF challenge page, SPA catch-all, dead endpoint ve redirect-only host'lar tarama öncesinde filtreleniyor. Body boyutu 50 byte altındaki cevaplar dead endpoint olarak işaretleniyor.

**P2-2: PostValidator Framework:** YENİ MODÜL `src/tools/scanners/post_validator.py`. Araç çıktılarını post-hoc doğrulamak için 4 temel primitif: `validate_status_meaningful()`, `validate_body_not_error()`, `validate_reflection()`, `validate_timing_anomaly()`. Her araç wrapper'ı tarafından çağrılabilir evrensel doğrulama katmanı.

**Phase 3 — Tool Confidence Calibration (6 item):**

**P3-1: Dalfox Type-Based Confidence:** `dalfox_wrapper.py` `_TYPE_CONFIDENCE` mapping: `G` (GET-param reflected) → 20, `R` (reflected confirmed) → 60, `V` (verified/DOM) → 80. Eski sabit 60 yerine XSS tipi bazlı granüler güven.

**P3-2: SQLMap Technique-Based Confidence:** `sqlmap_wrapper.py` `_TECH_CONFIDENCE` mapping: `time-based` → 40, `boolean-based` → 55 (eski sabit 65'ten düşürüldü). Blind SQLi tekniklerinin yüksek FP oranı yansıtıldı.

**P3-3: Subdomain Takeover Unknown CNAME:** `subdomain_takeover.py` bilinmeyen CNAME pattern'ları için confidence 20'ye düşürüldü. Sadece bilinen vulnerable servisler (GitHub Pages, Heroku, S3 vb.) yüksek güven alıyor.

**P3-4: SearchSploit Version Verification:** `searchsploit_wrapper.py` artık tespit edilen versiyon ile exploit başlığındaki versiyonu karşılaştırıyor. Versiyon eşleşmesi: conf=25, kısmi eşleşme: conf=15, eşleşme yok: conf=10.

**P3-5: Commix Blind Confidence:** `commix_wrapper.py` blind command injection bulguları için confidence 35'e düşürüldü (eski 60'tan). Confirmed execution kanıtı olan bulgular yüksek güven koruyor.

**P3-6: SSRFMap Generic Confidence:** `ssrfmap_wrapper.py` genel SSRF bulguları için confidence 55'e kalibre edildi. OOB callback veya data extraction kanıtı olan bulgular ayrıca yükseltiliyor.

**Phase 4 — HUNTER Deep Probe Statistical Baseline (4 item):**

**P4-1: Statistical Baseline Collection:** `deep_probe.py` artık her hedef endpoint için 3 baseline request gönderiyor (`_NUM_BASELINE=3`). `ProbeTarget` modeline `baseline_timing_mean`, `baseline_timing_std`, `baseline_body_hash` alanları eklendi. `hashlib` ve `statistics` import edildi.

**P4-2: Smart Indicator Detection:** `_detect_indicators()` tamamen yeniden yazıldı. XSS tespitinde context-aware analiz (unescaped reflection, event handler, script tag context). SQLi timing tespitinde istatistiksel karşılaştırma (baseline mean + 3*std threshold). SSTI tespitinde çoklu hesaplama doğrulaması ({{7*7}}=49 VE {{7*8}}=56). RCE tespitinde genişletilmiş output pattern'ları.

**P4-3: Hypothesis Prompt Enrichment:** Brain'e gönderilen hipotez prompt'u artık baseline timing istatistiklerini ve body hash'i içeriyor. LLM, baseline'dan sapma olmayan sonuçları daha doğru değerlendirebiliyor.

**P4-4: Stall Detection & Blind Type Handling:** Stall detection threshold 5→7'ye yükseltildi, pencere [-6:] kullanılıyor. `_BLIND_TYPES` seti (time-based SQLi, blind SSRF, blind XSS, blind command injection) tanımlandı — bu türler 2x iterasyon alarak daha fazla sinyal toplama şansı elde ediyor.

**Phase 5 — Benchmark Lab TPR/FPR Measurement (5 item):**

**P5-1: Benchmark Lab Core Engine:** YENİ MODÜL `src/analysis/benchmark_lab.py` (~500 satır). 3-kategorili bulgu sınıflandırması: TP (expected class eşleşmesi), FP (expected'da yok VE noise'da yok), Noise (acceptable_noise — tüm metriklerden hariç). `_VULN_SYNONYMS` ~120 entry'lik kanonik vuln type map'i (SQL injection varyantları, XSS türleri, RCE, LFI, CSRF, IDOR/BOLA, deserialization, mass assignment, SSRF, GraphQL vb.). `normalize_vuln_type()` lowercase + underscore + synonym dönüşümü. 7 dataclass: `ClassifiedFinding`, `LabBenchmarkResult` (to_dict), `BenchmarkSuiteResult` (to_dict), `CalibrationRecommendation`. 5 sınıf: `BenchmarkEvaluator` (evaluate/evaluate_suite ile per-lab ve suite-level TPR/Precision/FPR(FDR)/F1 hesaplama, per-class breakdown, missed_classes ve extra_types tespiti), `LabManager` (Docker compose start/stop, async health check, wait_for_ready polling), `BenchmarkScanner` (subprocess ile lab tarama), `CalibrationEngine` (TPR_TARGET=0.80, FPR_TARGET=0.20 hedefleriyle eşik önerisi — both bad/FPR high/TPR low/on target senaryoları), `BenchmarkReporter` (Markdown + JSON rapor üretimi, overall/per-lab/per-class breakdown tabloları).

**P5-2: Benchmark Lab Manifests:** `data/benchmark/manifests.json` — 7 vulnerable-by-design lab için zengin expected findings manifest. Her lab: url, docker_service, health_endpoint, health_status, setup_notes, expected_vulns (class + min_count + severity listesi), acceptable_noise (noise vuln type listesi). Labs: dvwa (9 expected vuln), juiceshop (7), webgoat (8), vampi (5), crapi (7), dvga (5), nodegoat (5).

**P5-3: Benchmark Runner Rewrite:** `scripts/benchmark_runner.py` tamamen yeniden yazıldı. Eski 306-satırlık TPR-only runner yerine `src/analysis/benchmark_lab` core module'ü kullanan ince CLI wrapper. argparse ile 12 flag: --lab, --findings, --findings-dir, --scan, --scan-timeout, --profile, --no-brain, --start-labs, --stop-labs, --health, --report, --calibrate, --threshold, --output.

**P5-4: CLI Benchmark Command:** `src/cli.py` içine `whai benchmark` komutu eklendi (14. komut). Typer ile --lab, --findings, --findings-dir, --scan, --report, --calibrate, --profile, --start-labs, --stop-labs parametreleri. Rich Panel/Table ile sonuç görselleştirme. CalibrationEngine ile eşik önerileri. BenchmarkReporter ile rapor kaydetme.

**P5-5: Regression Tests:** 61 yeni regresyon testi (12 test sınıfı): TestNormalizeVulnType (16), TestBenchmarkEvaluatorClassification (8), TestBenchmarkEvaluatorMetrics (6), TestBenchmarkEvaluatorPerClass (1), TestBenchmarkSuiteEvaluation (3), TestCalibrationEngine (6), TestBenchmarkReporter (3), TestLabManager (3), TestManifestLoading (4), TestLoadFindings (3), TestLabBenchmarkResult (1), TestEdgeCases (7).

**Phase 6 — Advanced Validation (4 item):**

**P6-1: Known Infrastructure IPs Database:** YENİ DOSYA `data/known_infrastructure_ips.json` — ~80 CIDR aralığı, 10 sağlayıcı kategorisi (cloudflare, akamai, fastly, aws_cloudfront, google_cloud_cdn, azure_cdn, sucuri, incapsula, stackpath, dns_providers). `interactsh_wrapper.py` başlangıçta JSON dosyasını yükler; dosya bulunamazsa `_INLINE_FALLBACK_CIDRS` kullanılır.

**P6-2: Multi-Stage Verification Gate:** `full_scan.py` reporting aşamasına çok aşamalı doğrulama kapısı eklendi. `_STRONG_EVIDENCE_KEYWORDS` (16 anahtar kelime: `confirmed`, `verified`, `extracted`, `executed`, `reproduced`, `callback_received`, `data_leaked`, `shell_obtained` vb.) bulgu evidence/description alanlarında aranıyor. CRITICAL severity + confidence<75 → HIGH'a düşürülüyor. HIGH severity + confidence<70 → MEDIUM'a düşürülüyor. Düşürülen bulgulara `original_severity` ve `downgrade_reason` metadata'sı ekleniyor.

**P6-3: CORS Wildcard Not Reportable:** `cors_checker.py` artık `Access-Control-Allow-Origin: *` (wildcard) bulunan endpoint'ler için HİÇBİR bulgu üretmiyor. Wildcard CORS spesifikasyon gereği credential göndermez, dolayısıyla güvenlik riski oluşturmaz. Sadece reflected origin + `Access-Control-Allow-Credentials: true` kombinasyonu raporlanıyor.

**Test Suite:** 563 yeni regresyon testi (7 yeni test dosyası): `test_v5_p0_regression.py` (21), `test_v5_p1_regression.py` (39), `test_v5_p2_regression.py` (25), `test_v5_p3_regression.py` (30), `test_v5_p4_regression.py` (25), `test_v5_p6_regression.py` (27), `test_benchmark_lab.py` (61). **Test suite: 1862 → 2425 tests, 0 failures, 2 skipped.**

### v3.3.1 Deep Audit & Quality Hardening (NEXT_LEVEL_PLAN_V25)

Üç paralel derin-arama audit'i (brain/workflow katmanı, tool/FP katmanı, pipeline/integration katmanı) sonucunda ~31 hata tespit edildi. Tüm CRITICAL (4/4), HIGH (7/8) ve en etkili MEDIUM (8/9) hatalar düzeltildi:

**CRITICAL Bug Fixes (4/4):**

**C-1: FP Detector Early-Layer Cap:** `src/fp_engine/fp_detector.py` — Layer 1a/1b/1c toplam penaltısı `max(total, -40)` ile sınırlandırıldı. Önceden aşırı early-layer penaltı (-75 gibi) sonraki katmanların kararlarını geçersiz kılıyordu.

**C-2: Brain-Down Recovery Path:** `src/fp_engine/fp_detector.py` — `_brain_down` bayrağı artık 300s sonra otomatik olarak recovery'ye geçiyor. Brain fallback kodu `import time` eksikliği nedeniyle `NameError` ile çöküyordu; düzeltildi.

**C-3: api_scan.py State Sync + Handler Ordering:** `src/workflow/pipelines/api_scan.py` — `state.raw_findings` senkronizasyonu raporlama öncesine eklendi. Handler kayıt sırası düzeltildi: `scope_analysis` → `passive_recon` → `active_recon` → `enumeration` → `vulnerability_scan` → `fp_elimination` → `reporting`.

**C-4: Orchestrator force_transition():** `src/workflow/orchestrator.py` + `src/workflow/state_machine.py` — Yeni `force_transition()` metodu eklendi. Orchestrator artık stage sonrası `can_transition()` başarısız olduğunda `force_transition()` ile ilerleme sağlıyor.

**HIGH Bug Fixes (7/8):**

**H-1: web_app.py _finding_to_dict 9→21 Fields:** `src/workflow/pipelines/web_app.py` — Finding dict dönüşümünde 12 alan eksikti (evidence, http_request, http_response, cve_id, cwe_id, cvss_score, poc_code, poc_confirmed, remediation, references, metadata, tags). full_scan.py ile tutarlı hale getirildi.

**H-2: GlobalFindingStore Dead SQL Param:** `src/analysis/global_finding_store.py` — `_ensure_tables()` içinde `(?,)` SQL parametresi `last_seen_scan_id` sütununun default value'sunda kullanılıyordu (DDL'de parametre desteklenmez). Kaldırıldı.

**H-3: BenchmarkLab Normalized Sets:** `src/analysis/benchmark_lab.py` — `evaluate()` içinde `expected_classes` ve `noise_classes` `set()` yerine `{normalize_vuln_type(c) for c in ...}` ile normalize edildi. Büyük/küçük harf ve synonym farkları FP/TP sınıflandırmasını bozmuyordu.

**H-4: CorrelationEngine OOB Chain Limit:** `src/analysis/correlation_engine.py` — `_find_oob_chains()` max 2 zincir üretiyor (önceden sınırsız). Log seviyesi `logger.info` → `logger.debug`.

**H-5: CLI Version + switch_mode YAML Persistence:** `src/cli.py` — `__version__` "3.3" olarak güncellendi. `switch_mode` komutu artık settings.yaml dosyasını gerçekten güncelliyor.

**H-6: Evidence Quality Gate PoC Bypass:** `src/fp_engine/evidence_quality_gate.py` — `poc_confirmed=True` olan bulgular requires_reproduction kontrolünden muaf.

**H-7: Notification Webhook Validation:** `src/integrations/notification.py` — Boş string webhook URL'leri artık kanal oluşturmayı engellemiyor (erken return).

**MEDIUM Bug Fixes (8/9):**

**M-1: EvidenceAggregator getattr Safety:** `src/reporting/evidence/evidence_aggregator.py` — `finding.http_request` vb. `getattr(finding, "http_request", "")` ile güvenli erişime çevrildi.

**M-2: ScanProfiler Sentinel Total:** `src/analysis/scan_profiler.py` — `total_duration` 0 olduğunda bölme hatası engellemek için `max(total, 0.001)` guard eklendi.

**M-3: AutoDraft Severity Guard:** `src/reporting/auto_draft.py` — `severity` None/non-string olduğunda `_coerce_str()` ile güvenli dönüşüm.

**M-4–M-8:** Diğer küçük güvenlik ve güvenilirlik düzeltmeleri (detaylar `docs/plans/NEXT_LEVEL_PLAN_V25.md` içinde).

**Brain Prompt Regression Test Suite (T1-2):**

**Router Comprehensive Tests:** `tests/test_brain/test_router_comprehensive.py` — 77 parametrize test: SECONDARY routing (30 task type), PRIMARY routing (20 task type), BOTH routing (5 task type), priority ordering, default fallback, override bypass, history tracking, custom rules, stats counting, regex matching. **77 passed in 0.23s.**

**Intelligence Engine Tests:** `tests/test_brain/test_intelligence_comprehensive.py` — 56 test (16 test sınıfı): TestDataModelDefaults (5), TestAnalyzeReconAndPlan (3), TestGenerateCreativeAttackNarratives (2), TestGenerateDynamicTestCases (3), TestDecideNextAction (5), TestVerifyFinding (4), TestGenerateNucleiTemplate (3), TestGeneratePoc (3), TestEnrichReportFinding (2), TestBrainCache (2), TestSafeJsonParse (7), TestBrainDownRecovery (4), TestBrainQualityMetrics (3), TestCredentialSanitization (3), TestURLClustering (3), TestCompactTechStack (2). **56 passed in 0.26s.**

**Prompt Template Tests:** `tests/test_brain/test_prompt_templates.py` — 35 test (8 test sınıfı): TestReconPrompts (4), TestTriagePrompts (7), TestAnalysisPrompts (6), TestExploitPrompts (6), TestReportPrompts (4), TestFPEliminationPrompts (3), TestPromptEdgeCases (5). Tüm 27 public `build_*` fonksiyonu 6 prompt dosyasında kapsanıyor. **35 passed in 0.18s.**

**Audit Regression Tests:** `tests/test_integration/test_v25_audit_fixes.py` — 39 regresyon testi: evidence quality gate (5), evidence aggregator (4), scan profiler (3), notification (4), auto draft (4), FP detector (19). **39 passed.**

**Test Suite:** 168 yeni brain test + 39 audit regresyon = 207 yeni test. **Test suite: 2425 → 2632 tests, 0 failures, 2 skipped.**

### v3.3.2 Güçlendirmeleri (Per-Scan Quality Report — V25 T5-3)

**Per-Scan Quality Report Module (T5-3):** YENİ MODÜL `src/analysis/scan_quality_report.py` — Her tarama çalıştırması için kapsamlı kalite değerlendirmesi. 4 dataclass: `QualityMetrics` (ham metrikler — araç, bulgu, severity, brain, kapsam, zamanlama, checker sayıları), `QualityScore` (0-100 bileşik skor, 5 boyut: tool_health=0.20, brain_health=0.20, fp_quality=0.25, coverage=0.20, evidence_quality=0.15), `QualityReport` (tam rapor — uyarılar, öneriler, karşılaştırma; `to_dict()` ve `to_markdown()`), `ScanQualityAnalyzer` (ana analiz sınıfı — `analyze()`, `_collect_metrics()`, `_compute_score()`, `_detect_warnings()`, `_generate_recommendations()`, `_compare()`).

**Pipeline Entegrasyonu:** `full_scan.py` `handle_reporting()` içine ScanProfiler'dan sonra, Auto-Draft'tan önce entegre edildi. Brain metrikleri `state.metadata["brain_metrics"]` veya `intelligence_engine.get_brain_metrics()` üzerinden alınır. Kalite raporu `output/reports/{session_id}/quality_report.md` olarak kaydedilir. Genel kalite skoru `state.metadata["scan_quality_score"]` içine yazılır.

**Test Suite:** 45 yeni regresyon testi (10 test sınıfı): TestSafeFloat (6), TestQualityMetrics (2), TestQualityScore (1), TestQualityReport (3), TestComputeScore (12), TestDetectWarnings (6), TestRecommendations (4), TestCompare (3), TestAnalyzeIntegration (4), TestEdgeCases (4). **Test suite: 2632 → 2677 tests, 0 failures, 2 skipped.**

### v3.3.3 Güçlendirmeleri (Deep Audit Hardening — V25 Integration/Crash Sweep)

Üretim akışını hedefleyen derin entegrasyon ve crash-risk temizliği. Amaç: session resume, secondary pipeline wiring, reporting/diff render yolları ve cross-scan dedup katmanında tip güvenliğini üretim-verisi altında sağlamlaştırmak.

**Critical Integration Fixes:** `src/workflow/pipelines/api_scan.py` artık `brain_engine`, `tool_executor`, `fp_detector` ve `human_callback` bağımlılıklarını `WorkflowOrchestrator`'a gerçekten enjekte eder. `src/workflow/session_manager.py` `auth_headers` ve `auth_roles` alanlarını `ScanSession` içine first-class olarak persist eder; `sync_from_workflow_state()` ve `sync_to_workflow_state()` resume sırasında auth state'i tam taşır. Aynı modül `completed_stages` ve `stage_results` için enum/string round-trip uyumluluğu kazandı: `completed_stages` workflow state'ten session metadata'ya kopyalanır, restore sırasında `WorkflowStage` enum'larına çevrilir, `stage_results` de `StageCheckpoint` üzerinden tekrar enum-key'li olarak kurulabilir.

**Crash-Risk Type Safety Sweep:** `src/analysis/correlation_engine.py` içine `_coerce_str()` eklendi; endpoint, host, OOB tag, teknoloji ve vuln-type alanlarında list/None girdileri artık `.lower()` / `.rstrip()` sırasında çökmez. `src/analysis/global_finding_store.py` `_coerce_str()` ile güçlendirildi; `_canonical_vuln_type()`, `_normalise_url()`, `finding_hash()` ve `record()` artık Swagger/API parser kaynaklı list tipli `url`, `parameter`, `severity`, `target`, `vulnerability_type`, `cve_id` alanlarını güvenli normalize eder. `src/workflow/pipelines/web_app.py` `_finding_to_dict()` artık `endpoint` alanını `target` yerine öncelikli kullanır; ayrıca OOB/Interactsh metadata (`interactsh_callback`, `oob_domain`, `oob_protocol`, `blind_verification`, `interaction_type`) ve PoC/reporting metadata'sını downstream'e taşır.

**Severity Rendering Guards:** `full_scan.py`, `orchestrator.py`, `intelligence.py`, `context_manager.py`, `executive_summary.py`, `html_formatter.py`, `markdown_formatter.py`, `diff_engine.py`, `diff_alerts.py`, `scan_control.py`, `cli.py`, `platform_submit/*.py` ve `nuclei_template_writer.py` genelinde `severity=None` kaynaklı `.lower()` / `.upper()` crash'leri kaldırıldı. Tüm kritik render/summary/alert yolları `str(... or default)` pattern'iyle güvenli hale getirildi.

**FP Engine Numeric Guarding:** `src/fp_engine/fp_detector.py` içine `_safe_float()` eklendi. Tool quirk penalties, WAF confidence, brain confidence, WAF artifact penalty ve response diff confidence delta artık malformed string / `None` değerlerde `ValueError` ile çökmez. FP context restore sırasında metadata status parsing için ek `try/except` koruması eklendi.

**Knowledge Update Resume Guard:** `src/workflow/pipelines/full_scan.py` knowledge-update özetindeki `completed_stages` serileştirmesi artık `getattr(stage, "value", str(stage))` kullanır; resume sonrası string stage değerleri yüzünden `AttributeError` oluşmaz.

**Regression Tests:** 9 yeni regresyon testi eklendi. Kapsam: session resume auth + enum restore, `api_scan` dependency wiring, `web_app` finding dönüşümünde endpoint/OOB metadata koruması, `CorrelationEngine` list-input coercion, `GlobalFindingStore` list-typed field record path ve reporting severity-None render yolları. **Test suite: 2677 → 2686 tests, 0 failures, 2 skipped.**

### v3.3.4 Güçlendirmeleri (Secondary Pipeline Reachability — V25 Dead-Wiring Sweep)

Tanımlı ama ana çalışma zincirinden seçilemeyen secondary pipeline'lar üretim giriş noktasına bağlandı. Amaç: `web_app`, `api_scan`, `network_scan` ve `quick_recon` builder'larının sadece modül düzeyinde var olması değil, CLI ve `main.py` üzerinden gerçekten seçilebilir ve resume-edilebilir olması.

**Pipeline Selector Wiring:** `src/main.py` içine `_build_pipeline_orchestrator()` eklendi. Bu helper `full`, `web`, `api`, `network`, `quick_recon` pipeline tipleri arasında tek merkezden seçim yapar ve brain/tool executor/FP detector/session manager/router bağımlılıklarını tutarlı şekilde builder'lara geçirir. `initialize_app()` ve `run_scan()` artık `pipeline_type` parametresi kabul eder; `resume_scan()` pipeline tipini session metadata'dan (`workflow_metadata["pipeline_type"]`) geri yükler.

**CLI Integration:** `src/cli.py` `scan` komutuna `--pipeline` seçeneği eklendi (`full | web | api | network | quick_recon`). Değer doğrulaması, kullanıcı paneli özeti ve `run_scan(..., pipeline_type=...)` çağrısı bağlandı. Böylece secondary pipeline'lar ilk kez normal kullanıcı akışından reachable hale geldi.

**Secondary Builder Consistency:** `src/workflow/pipelines/network_scan.py` ve `src/workflow/pipelines/quick_recon.py` builder imzaları `tool_executor`, `fp_detector` ve `human_callback` kabul edecek şekilde genişletildi. `WorkflowOrchestrator` oluşturulurken bu bağımlılıklar artık `full_scan`, `web_app` ve `api_scan` ile aynı seviyede enjekte edilir.

**Regression Tests:** 4 yeni regresyon testi eklendi. Kapsam: `main._build_pipeline_orchestrator()` doğru builder seçimi, bilinmeyen pipeline reddi, `network_scan` ve `quick_recon` builder dependency injection tutarlılığı. **Test suite: 2686 → 2690 tests, 0 failures, 2 skipped.**

### v3.4 Güçlendirmeleri (Radical Scan Quality Revolution — FP Elimination & Coverage Expansion)

Dropbox.com üretim taramasının (102 ham bulgu → 0 raporlanabilir) kök-neden analizine dayalı 7 fazlı radikal kalite devrimi. İki sistemik sorunun eş zamanlı çözümü: (1) doğrulama boşluklarından kaynaklanan masif false positive üretimi, (2) saldırı kapsamının felaket düzeyinde düşük olması (Nuclei yalnızca 10 host, Dalfox yalnızca 20 URL, SQLMap endpoint'lerin %10'u).

**Phase 1 — Kritik FP Kaynak Eliminasyonu (5 düzeltme):**

**P1-1: ResponseValidator 401/407 Reddi:** `src/utils/response_validator.py` — Check 1c eklendi: status 401/407 → `is_auth_redirect=True`, `confidence_modifier=-20.0`. `www-authenticate` header parse ederek Basic Auth tespiti. Tüm ResponseValidator kullanan checker'lara kaskad etkisi.

**P1-2: Sensitive URL Finder HTTP Doğrulaması:** `src/tools/scanners/custom_checks/sensitive_url_finder.py` — `verify_sensitive_urls()` async fonksiyonu eklendi. Regex eşleşmesinden sonra `httpx.AsyncClient.head()` → GET fallback ile doğrulama. Sadece 200 status + >50 byte body olan URL'ler bulgu üretir. 401/403/404/5xx reddedilir. `asyncio.Semaphore(5)` ile eşzamanlı doğrulama.

**P1-3: JS Analyzer Status Kontrolü:** `src/tools/scanners/custom_checks/js_analyzer.py` — `_fetch_js()` artık sadece HTTP 200 dönen JS dosyalarını analiz eder. 404/403/5xx sayfalarında DOM XSS FP'leri engellendi.

**P1-4: Cookie Checker Status Reddi:** `src/tools/scanners/custom_checks/cookie_checker.py` — 401/403/407 (auth gerekli), 404/410 (bulunamadı) ve 5xx (sunucu hatası) status code'ları reddedilir. WAF/auth response'larından cookie analizi engellendi.

**P1-5: Executor Profiler Kwargs Düzeltmesi:** `src/tools/executor.py` — PerfProfiler `record_tool()` çağrısı doğru keyword argümanlarıyla güncellendi.

**Phase 2 — Host-Düzeyi İstihbarat (3 düzeltme):**

**P2-1: Preflight Auth Tespiti:** `src/workflow/pipelines/full_scan.py` `_preflight_check()` — Preflight sonuçları host bazında toplanır. Aynı host'ta ≥3 path 401/403 dönerse VEYA >%60 auth oranı varsa host `auth_gated=True` olarak `state.metadata["host_profiles"]` içinde işaretlenir. Auth-gated host'lar auth_headers yoksa downstream checker'lardan atlanır.

**P2-2: Staging Host Deprioritizasyonu:** `src/workflow/pipelines/full_scan.py` — "staging"/"stage" kelimeleri +12 öncelik anahtar kelimelerinden çıkarılıp -5 deprioritizasyon listesine taşındı. Staging host'lar İLK değil SON taranır.

**P2-3: Auth-Gated Host Filtresi:** `src/workflow/pipelines/full_scan.py` — `_host_urls` oluşturma noktalarında auth-gated host filter uygulanır. `auth_headers` yoksa auth_gated host'lar atlanır.

**Phase 3 — Saldırı Kapsamı Devrimi (6 düzeltme):**

**P3-1: Nuclei Dinamik Hedef Ölçekleme:** `src/workflow/pipelines/full_scan.py` — Nuclei hedef sayısı `targets[:10]` yerine `targets[:max(25, len(targets)//3)]`. AGGRESSIVE: `max(50, //2)`, STEALTH: `max(15, //4)`. Dropbox'ın 14 host'unun TAMAMI taranır (eski 10 yerine).

**P3-2: Nuclei Katmanlı Geçiş Stratejisi:** `src/workflow/pipelines/full_scan.py` — 7 eşit ardıl geçiş yerine 3 katmanlı strateji: Fast pass (kritik template'ler, TÜM host'lar, 10dk), Medium pass (üst %50 host, 15dk: exposures+misconfig), Deep pass (üst %25 host, 20dk: tamamı). Fast pass TÜM host'larda kritik zafiyetleri yakalar.

**P3-3: Dalfox Kapsam Genişletme + Mining:** `src/workflow/pipelines/full_scan.py` — `param_urls[:20]` yerine `max(50, len(param_urls)//4)`. `--mining-dict` ve `--mining-dom` bayrakları etkinleştirildi. XSS kapsamı %4 → %25+. Mining gizli parametreleri keşfeder.

**P3-4: SQLMap Derinlik Artışı:** `src/tools/scanners/sqlmap_wrapper.py` — BALANCED profili: level 2→3, risk 1→2, technique BEU→BEUST (Time-based + Stacked eklendi), time-sec 5→10. Blind SQLi varyantları tespit edilir.

**P3-5: SQLMap Kapsam + Parametre Önceliklendirme:** `src/workflow/pipelines/full_scan.py` — `deduped_params[:40]` yerine `max(80, len(deduped_params)//3)`. Yüksek-değer parametreler (id, user, search, query vb.) önce test edilir.

**P3-6: Dir Fuzzing + GraphQL Ölçekleme:** `src/workflow/pipelines/full_scan.py` — Enumeration: `live_hosts[:5]` yerine `max(8, len(live_hosts)//3)`. GraphQL introspection aynı dinamik ölçekleme formülü.

**Phase 4 — FP Eşik Sertleştirmesi (4 düzeltme):**

**P4-1: Severity-Katmanlı Raporlama Eşiği:** `src/workflow/pipelines/full_scan.py` — `_min_conf = 60.0` MEDIUM/HIGH/CRITICAL severity için, `50.0` LOW/INFO için. Belirsiz bulgular raporlanmadan elenir.

**P4-2: SearchSploit FP Ceza Artışı:** `src/fp_engine/patterns/known_fps.py` — FP-SPLOIT-001 penaltı -20→-35, FP-SEARCHSPLOIT-001 penaltı -15→-30. SearchSploit gürültüsü agresif cezalandırılır.

**P4-3: Erken-Katman Sınır Kaldırma:** `src/fp_engine/fp_detector.py` — Layer 1a/1b/1c toplam penaltısındaki `-40` sınırı KALDIRILDI. Güçlü FP kalıp eşleşmeleri artık kesin karar verebilir.

**P4-4: Brain Override Sınırı:** `src/fp_engine/fp_detector.py` — Dedektör skoru <20 iken brain pozitif delta verirse, nihai skor max(45, dedektör+25) ile sınırlandırılır. Brain'in düşük-güvenli bulguları tek başına doğrulanmış yapması engellendi.

**Phase 5 — Akıllı Hedef Seçimi (2 düzeltme):**

**P5-1: Endpoint-Checker Yönlendirme:** `src/workflow/pipelines/full_scan.py` — 4 checker'a akıllı koruma eklendi: `_run_graphql_deep()` yalnızca /graphql endpoint veya GraphQL teknolojisi tespit edildiğinde, `_run_websocket()` yalnızca ws:///wss:///socket/websocket sinyalleri varsa, `_run_cloud_infra()` yalnızca bulut teknolojisi (aws, azure, gcp, k8s, docker vb.) varsa, `_run_cicd_checker()` yalnızca CI/CD teknolojisi (jenkins, gitlab vb.) tespit edildiğinde çalışır.

**P5-2: Parametre İstihbaratı:** YENİ MODÜL `src/utils/param_intelligence.py` — 8 saldırı türü için parametre sınıflandırma tabloları (sqli, xss, ssrf, lfi, idor, ssti, rce, redirect). `classify_param(name) → list[AttackType]`, `filter_urls_for_attack(urls, type) → list[str]`, `prioritize_params_for_sqli(params) → list[str]`.

**Phase 6 — No-Brain Mod Optimizasyonu (2 düzeltme):**

**P6-1: Brain Yokluğu Atlama:** `src/workflow/pipelines/full_scan.py` — `handle_vulnerability_scan()` başında `_brain_available = bool(intel and intel.is_available)` bayrağı ayarlanır. Brain yokken tüm brain-bağımlı fazlar (HUNTER A/B, yaratıcı saldırı anlatıları, dinamik test case üretimi) zaten mevcut `if intel and intel.is_available:` korumaları ile atlanır; bayrak durumu loglanır.

**P6-2: Heuristik FP Kompanzasyonu:** `src/fp_engine/fp_detector.py` — Brain yokken (`_brain_ok = False`): Layer 1 penaltıları 1.5x çarpanla güçlendirilir (brain yokluğunda daha agresif FP eliminasyonu). Layer 6 re-request doğrulaması LOW severity bulgular için de tetiklenir (normalde sadece MEDIUM+).

**Phase 7 — SearchSploit Radikal Yenileme (3 düzeltme):**

**P7-1: Global Bulgu Sınırı:** `src/tools/exploit/searchsploit_wrapper.py` — `_MAX_FINDINGS_TOTAL = 15` tüm arama terimleri genelinde. Sınıra ulaşılınca arama durur.

**P7-2: Version-Strict Modu:** `src/tools/exploit/searchsploit_wrapper.py` — `_versions_compatible()` sıkılaştırıldı: minor versiyon farkı 5→2'ye düşürüldü, parse hatalarında `False` döner (eski `True` yerine). "nginx 1.14" artık "nginx 1.25.3" için reddedilir.

**P7-3: Minimum Güven Tabanı:** `src/tools/exploit/searchsploit_wrapper.py` — `_MIN_CONFIDENCE = 20.0`. Güven skoru <20 olan bulgular döndürülmeden önce düşürülür.

**Kanıtlanmış Etki (Dropbox.com Karşılaştırma):**
| Metrik | v3.3.4 (Eski) | v3.4 (Yeni) |
|--------|--------------|-------------|
| Ham Bulgular | 102 | Kalite odaklı — daha az ama doğrulanmış |
| Auth-Gated Host FP | ~18+ (cloud_checker) | 0 (401/403 host filter) |
| Sensitive URL FP | ~7+ (regex-only) | 0 (HTTP doğrulaması) |
| SearchSploit Gürültü | ~30+ | Max 15, conf≥20, version-strict |
| Nuclei Kapsam | 10/14 host | 14/14 host (tamamı) |
| XSS Kapsam | %4 | %25+ (param mining dahil) |
| SQLi Derinlik | level 2, risk 1 | level 3, risk 2, BEUST |
| FP Engine Koruma | -40 sınır, brain override | Sınır yok, brain max(45) cap |

**Test suite: 2690 tests, 0 failures, 2 skipped.**

### v3.5 Güçlendirmeleri (Agentic Pipeline Revolution — ReAct Agent Loop)

Sabit 10-aşamalı pipeline'ın (orchestrator.py + 8100 satır full_scan.py monoliti) yerine, BaronLLM'in her araç çalıştırmasından sonra "şimdi ne yapmalıyım?" sorusuna cevap verdiği ReAct-tarzı otonom agent döngüsüne geçiş. Brain artık "danışman" değil, taramayı aktif olarak yöneten "orkestratör" rolünde.

**Temel Mimari Değişiklik — OBSERVE → THINK → ACT → EVALUATE → DECIDE:**
```
while budget_remaining and not brain_says_done:
    OBSERVE  → WorkingMemory'den durum özetini oku
    THINK    → Brain'e "Şimdi ne yapmalıyım?" sor (AgentContext ile)
    ACT      → Brain'in seçtiği ToolUnit'i çalıştır
    EVALUATE → Sonucu brain ile değerlendir (kalite, deep-dive gerekli mi?)
    DECIDE   → Devam et / Aşama değiştir / Geriye dön / Dur
```

**Eski vs Yeni Mimari:**
| Özellik | v3.4 (Eski) | v3.5 (Yeni) |
|---------|-------------|-------------|
| Pipeline | Sabit 10 aşama, sıralı | Brain-driven ReAct loop |
| Brain Rolü | 6 noktada danışman | Her iterasyonda orkestratör |
| Geri Dönüş | Yok (sadece ileri+skip) | Max 2 per stage backward |
| Araç Seçimi | Hardcoded sıra | Brain dinamik seçim |
| Araç Çıktısı | İzole (append → devam) | Sonraki kararı etkiler |
| Hipotez | Yok | WorkingMemory'de izlenir |
| Saldırı Zinciri | Post-hoc correlation | Gerçek zamanlı brain planlama |

**Yeni Dosyalar (6 modül, ~3000 satır):**

**ToolUnit Abstraction (Phase 1.1):** `src/workflow/tool_unit.py` — `ToolUnit` ABC, `ToolUnitResult` dataclass, `ToolUnitRegistry` container, `UnitCategory` enum (13 kategori: subdomain, port_scan, web_discovery, tech_detect, dns, osint, fuzzing, scanner, custom_check, exploit, network, crypto, proxy). Her ToolUnit: `unit_id`, `display_name`, `category`, `stage`, `prerequisites`, `parallel_safe`, `execute(state, options) → ToolUnitResult`.

**Working Memory (Phase 1.2):** `src/brain/memory/working_memory.py` — `WorkingMemory` sınıfı: iterasyon geçmişi, hipotez yönetimi (Hypothesis + HypothesisStatus enum: ACTIVE/CONFIRMED/REFUTED/ABANDONED), `TargetProfile` dataclass (host'lar, teknolojiler, portlar, CDN/WAF/auth bilgileri), `FindingsSummary` (severity dağılımı, araç-vuln matrisi), `TimeBudget` (toplam/kalan süre, profil bazlı limitler), `ObservationSummarizer` (token-efficient durum özeti).

**Agent Context (Phase 1.3):** `src/workflow/agent_context.py` — `AgentAction` enum (12 aksiyon: RUN_UNIT, PARALLEL_UNITS, SKIP_UNIT, SWITCH_STAGE, GO_BACK_STAGE, DEEP_DIVE, FORMULATE_HYPOTHESIS, CHAIN_ATTACK, REQUEST_HUMAN, ADJUST_STRATEGY, COMPLETE_STAGE, END_SCAN), `AgentDecision` dataclass (action, unit_id, reasoning, confidence, stage_target, parallel_units), `EvaluationResult` dataclass, `UnitDescriptor` (brain'e ToolUnit özetleri), `AgentContext.build()` classmethod (tam bağlam nesnesi oluşturma).

**Agent Prompts (Phase 1.4):** `src/brain/prompts/agent_prompts.py` — `AGENT_SYSTEM_PROMPT` (ReAct agent rolü), `EVALUATOR_SYSTEM_PROMPT` (sonuç değerlendirme), `build_agent_think_prompt()` (tam bağlam + mevcut birimler + tamamlananlar + bütçe → JSON karar), `build_agent_evaluate_prompt()` (araç sonucu + bulgular → kalite değerlendirmesi), `build_stage_selection_prompt()` (aşama geçiş kararı), `build_chain_attack_prompt()` (çoklu bulgudan saldırı zinciri planlama).

**Agent Orchestrator (Phase 2):** `src/workflow/agent_orchestrator.py` — ReAct döngüsünün merkezî orkestratörü. `AgentOrchestrator` sınıfı: `run(target, scope) → WorkflowState` ana giriş noktası, `_agent_loop()` iteratif karar döngüsü, `_brain_think()` brain karar çağrısı, `_brain_evaluate()` sonuç değerlendirmesi, `_execute_unit()` tekli birim çalıştırma, `_execute_parallel()` paralel birim çalıştırma (max 4), `_handle_go_back()` geri dönüş (max 2 per stage), `_handle_deep_dive()` derinleşme, `_detect_stall()` ilerleme durgunluğu tespiti (3 ardışık boş iterasyon), `_maybe_reflect()` her 5 iterasyonda self-reflection, `_run_fp_elimination()` toplu FP analizi, `_run_reporting()` rapor üretimi, `_run_knowledge_update()` öğrenme kayıt. `BrainRequiredError` exception: brain erişilemezse tarama iptal.

**Agentic Pipeline Builder (Phase 6):** `src/workflow/pipelines/agentic_scan.py` — `build_agentic_pipeline()` factory + `register_all_tool_units()`. 60+ SecurityTool'u gruplandırılmış ToolUnit'lere sarar. Tool→Stage mapping: subdomain/dns/osint→PASSIVE_RECON, web_discovery/tech_detect/port_scan→ACTIVE_RECON, fuzzing/api→ENUMERATION, scanners/custom_checks/crypto→VULNERABILITY_SCAN, exploit→EXPLOITATION.

**Değiştirilen Dosyalar:**

**State Machine Backward Transitions (Phase 1.5):** `src/workflow/state_machine.py` — 5 yeni geri dönüş transition'ı eklendi: VULNERABILITY_SCAN→ACTIVE_RECON (yeni subdomain keşfi), VULNERABILITY_SCAN→ENUMERATION (yeni endpoint keşfi), FP_ELIMINATION→VULNERABILITY_SCAN (FP analizi daha fazla test önerdi), ENUMERATION→ACTIVE_RECON (yeni host keşfi), ATTACK_SURFACE_MAP→ENUMERATION (strateji yeniden enumeration gerektiriyor). `MAX_BACKWARD_PER_STAGE = 2` limiti ile sonsuz loop engeli.

**BrainRouter Agentic Rules (Phase 3):** `src/brain/router.py` — 4 yeni routing kuralı: `agent_decide|agent_think|next_action` → SECONDARY (hız kritik), `agent_evaluate|evaluate_result|tool_result_analysis` → PRIMARY (derin analiz), `stage_select|stage_transition|workflow_route` → SECONDARY (hızlı karar), `chain_attack|attack_chain|multi_step_exploit` → PRIMARY (derin reasoning).

**IntelligenceEngine Agent Methods (Phase 3):** `src/brain/intelligence.py` — 3 yeni convenience metot: `agent_decide_stage(context_summary, available_units, completed_units, time_budget, profile)` → JSON karar dict, `agent_evaluate_result(unit_id, output_summary, findings, severity_dist, context)` → kalite değerlendirme dict, `agent_plan_attack_chain(initial_finding, available_tools, target_context, profile)` → zincir planı dict.

**main.py Agentic Pipeline Wiring:** `src/main.py` — `_build_pipeline_orchestrator()` pipeline builders dict'ine `"agentic"` entry eklendi. `build_agentic_pipeline()` factory import ve çağrı.

**CLI Agentic Pipeline Support:** `src/cli.py` — `--pipeline` seçeneğine `agentic` eklendi. `_valid_pipelines` tuple'ına `"agentic"` eklendi. `--max-iterations` (int, opsiyonel) ve `--time-budget` (float saat, opsiyonel) flag'ları eklendi — profil bazlı varsayılanları override eder. `run_scan()` → `AgentOrchestrator` zincirine aktarılır.

**Güvenlik Rayları (Safety Rails):**
- Brain erişilemezse tarama başlatılmaz (`BrainRequiredError`)
- Scope validator her ToolUnit çalıştırmasından önce kontrol
- `MAX_BACKWARD_PER_STAGE = 2` — sonsuz geri dönüş engeli
- `max_iterations` profil bazlı limit (stealth=40, balanced=60, aggressive=100)
- `time_budget` profil bazlı süre limiti (stealth=2h, balanced=3h, aggressive=5h)
- Stall detection: 3 ardışık ilerleme olmayan iterasyon → WARNING + strategy change
- Payload safety filter korundu (yıkıcı komut engelleme)

### Remote Brain Bağlantı Mimarisi (v2.2)

Bot, LM Studio'yu uzak bir Mac üzerinde çalıştırır. Bağlantı SSH tunnel üzerinden sağlanır:

```
[Kali Linux (Bot)]  ──SSH Tunnel──▶  [Mac (LM Studio)]
127.0.0.1:1239     ◀──────────────   127.0.0.1:1239
```

**Bağlantı Katmanları:**
1. **SSH Tunnel** (`scripts/ssh_tunnel.sh`): `ssh -L 1239:127.0.0.1:1239 mac@192.168.1.10` — auto-reconnect, PID tracking, health check
2. **API Authentication**: LM Studio API token → `Authorization: Bearer <token>` header (`.env` → `WHAI_PRIMARY_API_KEY`)
3. **Pre-Scan Health Check** (`verify_brain_ready()`): Scan başlamadan ÖNCE 3 aşamalı kontrol:
   - SSH tunnel alive? → Değilse otomatik `ssh_tunnel.sh start`
   - HTTP client oluşturulmuş mu? → Değilse re-initialize
   - API erişilebilir ve model yüklü mü? → Değilse detaylı hata mesajı
4. **Runtime Auto-Recovery** (`_ensure_ssh_tunnel()`): Inference sırasında ConnectError → SSH tunnel check + reconnect → retry
5. **Watchdog** (`ssh_tunnel.sh watch`): Arka planda 30s aralıklarla tunnel kontrolü

**Kritik Kural:** Bot her zaman scan başlamadan önce `verify_brain_ready()` çağırır. Bu metod SSH tunnel'ı, API bağlantısını ve model durumunu kontrol eder. Başarısızlıkta detaylı hata mesajı ve `--no-brain` flag önerisi verilir.

---

## 🏗️ MİMARİ GENEL BAKIŞ

```
┌─────────────────────────────────────────────────────────────────┐
│                    WhiteHatHacker AI v3.5                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  CLI / TUI    │    │  Web Dashboard│    │  API Server  │       │
│  │  Interface    │    │  (FastAPI)    │    │  (REST/WS)   │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                    │                    │               │
│  ┌──────▼────────────────────▼────────────────────▼──────┐      │
│  │        AGENTIC ORCHESTRATOR (ReAct Loop) ★ v3.5       │      │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌────────┐  │      │
│  │  │ Working  │ │ Agent    │ │ ToolUnit  │ │ Safety │  │      │
│  │  │ Memory   │ │ Context  │ │ Registry  │ │ Rails  │  │      │
│  │  └──────────┘ └──────────┘ └───────────┘ └────────┘  │      │
│  │  OBSERVE → THINK → ACT → EVALUATE → DECIDE → (loop)  │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │              LEGACY WORKFLOW ORCHESTRATOR               │      │
│  │  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌─────────┐  │      │
│  │  │ State   │ │ Decision │ │ Task      │ │ Human   │  │      │
│  │  │ Machine │ │ Engine   │ │ Scheduler │ │ Gateway │  │      │
│  │  └─────────┘ └──────────┘ └───────────┘ └─────────┘  │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │                 DUAL BRAIN ENGINE                      │      │
│  │  ┌─────────────────┐    ┌─────────────────────────┐   │      │
│  │  │ BaronLLM v2     │    │ BaronLLM v2 /no_think │   │      │
│  │  │ (Deep Analysis) │    │ (Fast Triage)          │   │      │
│  │  └────────┬────────┘    └────────────┬────────────┘   │      │
│  │           │     ┌──────────┐         │                │      │
│  │           └─────│ Brain    │─────────┘                │      │
│  │                 │ Router   │                           │      │
│  │                 └──────────┘                           │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │           HUNTER MODE ENGINE (v2.2)                    │      │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │      │
│  │  │ Phase A:     │ │ Phase B:     │ │ Phase C:     │  │      │
│  │  │ Template Gen │ │ Deep Probe   │ │ PoC Execute  │  │      │
│  │  │ (Nuclei YAML)│ │ (Iterative)  │ │ (Evidence)   │  │      │
│  │  └──────────────┘ └──────────────┘ └──────────────┘  │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │              SECURITY TOOL ORCHESTRATOR                │      │
│  │                                                        │      │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐         │      │
│  │  │ Recon  │ │ Scan   │ │ Exploit│ │ Post   │         │      │
│  │  │ Tools  │ │ Tools  │ │ Tools  │ │ Tools  │         │      │
│  │  └────────┘ └────────┘ └────────┘ └────────┘         │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │       INTERACTSH OOB + ATTACK CHAIN CORRELATOR        │      │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────────────────┐  │      │
│  │  │ OOB      │ │ Chain     │ │ CVE Intelligence     │  │      │
│  │  │ Callback │ │ Discovery │ │ (SearchSploit)       │  │      │
│  │  └──────────┘ └───────────┘ └──────────────────────┘  │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │           FALSE POSITIVE ELIMINATION ENGINE            │      │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────────────────┐  │      │
│  │  │ Multi-   │ │ Context   │ │ Confidence Scoring   │  │      │
│  │  │ Verify   │ │ Analyzer  │ │ & Evidence Chain     │  │      │
│  │  └──────────┘ └───────────┘ └──────────────────────┘  │      │
│  └──────────────────────┬────────────────────────────────┘      │
│                          │                                       │
│  ┌──────────────────────▼────────────────────────────────┐      │
│  │              REPORTING & INTEGRATION                    │      │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────────────────┐  │      │
│  │  │ Report   │ │ Platform  │ │ Knowledge Base       │  │      │
│  │  │ Generator│ │ Adapters  │ │ & Learning           │  │      │
│  │  └──────────┘ └───────────┘ └──────────────────────┘  │      │
│  └───────────────────────────────────────────────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 PROJE DOSYA YAPISI

```
whitehathackerai-bot-2/
├── .github/
│   └── copilot-instructions.md          # Bu dosya
├── config/
│   ├── settings.yaml                    # Ana konfigürasyon
│   ├── models.yaml                      # Model konfigürasyonları
│   ├── tools.yaml                       # Araç tanımları ve parametreleri
│   ├── platforms.yaml                   # Bug bounty platform ayarları
│   ├── scopes/                          # Hedef scope tanımları
│   │   ├── example_scope.yaml
│   │   ├── automattic_gravatar.yaml
│   │   ├── coinbase.yaml
│   │   └── vimeo.yaml
│   └── profiles/                        # Tarama profilleri
│       ├── stealth.yaml                 # Düşük profil, yavaş tarama
│       ├── balanced.yaml                # Dengeli hız/derinlik
│       ├── aggressive.yaml              # Hızlı, kapsamlı
│       └── custom.yaml                  # Özelleştirilebilir
├── src/
│   ├── __init__.py
│   ├── main.py                          # Ana giriş noktası
│   ├── cli.py                           # CLI arayüzü (Rich/Typer)
│   │
│   ├── brain/                           # Dual Brain Engine
│   │   ├── __init__.py
│   │   ├── engine.py                    # Ana brain engine & model yönetimi
│   │   ├── router.py                    # Görev-model eşleme (brain router)
│   │   ├── prompts/                     # Sistem prompt'ları
│   │   │   ├── __init__.py
│   │   │   ├── recon_prompts.py         # Keşif aşaması prompt'ları
│   │   │   ├── analysis_prompts.py      # Analiz prompt'ları
│   │   │   ├── exploit_prompts.py       # Exploit stratejisi prompt'ları
│   │   │   ├── report_prompts.py        # Rapor yazma prompt'ları
│   │   │   ├── triage_prompts.py        # Triage ve önceliklendirme
│   │   │   ├── fp_elimination.py        # False positive eleme prompt'ları
│   │   │   └── agent_prompts.py         # ReAct agent system/think/evaluate prompts (v3.5)
│   │   ├── memory/                      # Bağlam & hafıza yönetimi
│   │   │   ├── __init__.py
│   │   │   ├── context_manager.py       # Conversation context
│   │   │   ├── knowledge_base.py        # Öğrenilen bilgiler DB
│   │   │   ├── vuln_patterns.py         # Bilinen zafiyet kalıpları
│   │   │   ├── session_memory.py        # Oturum hafızası
│   │   │   └── working_memory.py        # ReAct agent working memory (v3.5)
│   │   └── reasoning/                   # Akıl yürütme modülleri
│   │       ├── __init__.py
│   │       ├── chain_of_thought.py      # CoT reasoning
│   │       ├── attack_planner.py        # Saldırı planlaması
│   │       └── risk_assessor.py         # Risk değerlendirme
│   │
│   ├── workflow/                        # İş akışı yönetimi
│   │   ├── __init__.py
│   │   ├── orchestrator.py              # Ana orkestratör
│   │   ├── state_machine.py             # Durum makinesi
│   │   ├── task_scheduler.py            # Görev zamanlayıcı
│   │   ├── human_gateway.py             # İnsan onay mekanizması
│   │   ├── decision_engine.py           # Karar motoru
│   │   ├── continuous_monitor.py        # Continuous target monitoring loop (v2.7.7)
│   │   ├── campaign_manager.py          # Multi-target campaign orchestration (v2.7.7)
│   │   ├── tool_unit.py                 # ToolUnit ABC + Registry + UnitCategory (v3.5)
│   │   ├── agent_context.py             # AgentAction/AgentDecision/AgentContext (v3.5)
│   │   ├── agent_orchestrator.py        # ReAct loop orchestrator (v3.5)
│   │   └── pipelines/                   # Önceden tanımlı iş akışları
│   │       ├── __init__.py
│   │       ├── full_scan.py             # Tam tarama pipeline
│   │       ├── web_app.py               # Web uygulama pipeline
│   │       ├── api_scan.py              # API tarama pipeline
│   │       ├── network_scan.py          # Ağ tarama pipeline
│   │       ├── quick_recon.py           # Hızlı keşif pipeline
│   │       ├── asset_db_hooks.py        # AssetDB pipeline hooks (v2.4)
│   │       ├── incremental.py           # Incremental scan mode (v2.4)
│   │       ├── dry_run.py               # Dry-run preview mode (v2.4)
│   │       └── agentic_scan.py          # Agentic pipeline builder + ToolUnit wiring (v3.5)
│   │
│   ├── tools/                           # Güvenlik Araç Entegrasyonu
│   │   ├── __init__.py
│   │   ├── base.py                      # Temel araç sınıfı (abstract)
│   │   ├── registry.py                  # Araç kayıt ve keşif sistemi
│   │   ├── executor.py                  # Araç çalıştırma motoru
│   │   ├── parser.py                    # Çıktı ayrıştırma (unified)
│   │   │
│   │   ├── recon/                       # Keşif Araçları
│   │   │   ├── __init__.py
│   │   │   ├── subdomain/               # Subdomain keşfi
│   │   │   │   ├── __init__.py
│   │   │   │   ├── subfinder.py
│   │   │   │   ├── amass.py
│   │   │   │   ├── assetfinder.py
│   │   │   │   ├── findomain.py
│   │   │   │   ├── crt_sh.py
│   │   │   │   ├── knockpy.py
│   │   │   │   └── aggregator.py        # Subdomain sonuç birleştirici
│   │   │   ├── port_scan/               # Port tarama
│   │   │   │   ├── __init__.py
│   │   │   │   ├── nmap_wrapper.py
│   │   │   │   ├── masscan_wrapper.py
│   │   │   │   ├── rustscan_wrapper.py
│   │   │   │   └── service_detector.py
│   │   │   ├── web_discovery/           # Web keşfi
│   │   │   │   ├── __init__.py
│   │   │   │   ├── httpx_wrapper.py
│   │   │   │   ├── aquatone.py
│   │   │   │   ├── eyewitness.py
│   │   │   │   ├── waybackurls.py
│   │   │   │   ├── gau.py
│   │   │   │   ├── katana.py
│   │   │   │   ├── gospider.py
│   │   │   │   ├── hakrawler.py
│   │   │   │   ├── url_aggregator.py
│   │   │   │   ├── gf_patterns.py            # GF pattern URL classification (v2.4)
│   │   │   │   ├── csp_discovery.py          # CSP subdomain discovery (v2.4)
│   │   │   │   ├── vhost_fuzzer.py           # Virtual host fuzzing (v2.4)
│   │   │   │   └── sourcemap_extractor.py    # Source map analysis (v2.4)
│   │   │   ├── dns/                     # DNS keşfi
│   │   │   │   ├── __init__.py
│   │   │   │   ├── dnsrecon.py
│   │   │   │   ├── dnsx.py
│   │   │   │   ├── dig_wrapper.py
│   │   │   │   ├── zone_transfer.py
│   │   │   │   ├── mail_security.py          # SPF/DKIM/DMARC checker (v2.4)
│   │   │   │   └── reverse_ip.py             # Reverse IP lookup (v2.4)
│   │   │   ├── osint/                   # OSINT araçları
│   │   │   │   ├── __init__.py
│   │   │   │   ├── theHarvester.py
│   │   │   │   ├── shodan_wrapper.py
│   │   │   │   ├── censys_wrapper.py
│   │   │   │   ├── whois_wrapper.py
│   │   │   │   ├── google_dorking.py
│   │   │   │   ├── github_dorking.py
│   │   │   │   ├── github_secret_scanner.py   # GitHub secret search (v2.4)
│   │   │   │   ├── cloud_enum.py             # Cloud bucket enumeration (v2.4)
│   │   │   │   └── metadata_extractor.py     # Document metadata extraction (v2.4)
│   │   │   └── tech_detect/             # Teknoloji algılama
│   │   │       ├── __init__.py
│   │   │       ├── wappalyzer.py
│   │   │       ├── whatweb.py
│   │   │       ├── builtwith.py
│   │   │       ├── fingerprinter.py
│   │   │       ├── cdn_detector.py        # CDN detection (v2.4)
│   │   │       └── favicon_hasher.py      # Favicon hash tech detect (v2.4)
│   │   │
│   │   ├── scanners/                    # Zafiyet Tarayıcıları
│   │   │   ├── __init__.py
│   │   │   ├── nuclei_wrapper.py        # Nuclei template engine
│   │   │   ├── nikto_wrapper.py
│   │   │   ├── wpscan_wrapper.py
│   │   │   ├── sqlmap_wrapper.py
│   │   │   ├── xsstrike_wrapper.py
│   │   │   ├── dalfox_wrapper.py
│   │   │   ├── commix_wrapper.py
│   │   │   ├── ssrfmap_wrapper.py
│   │   │   ├── tplmap_wrapper.py
│   │   │   ├── jwt_tool_wrapper.py
│   │   │   ├── nosqlmap_wrapper.py
│   │   │   ├── crlfuzz_wrapper.py
│   │   │   ├── corsy_wrapper.py
│   │   │   ├── openredirex.py
│   │   │   ├── smuggler_wrapper.py
│   │   │   ├── arjun_wrapper.py         # Hidden param discovery
│   │   │   ├── paramspider_wrapper.py
│   │   │   ├── waf_strategy.py           # WAF fingerprint & adaptive strategy (v2.3)
│   │   │   ├── gf_router.py              # GF→Scanner auto-routing (v2.4)
│   │   │   ├── post_validator.py        # Post-validation framework (v3.3)
│   │   │   └── custom_checks/           # Özel kontroller (28 denetleyici)
│   │   │       ├── __init__.py
│   │   │       ├── idor_checker.py
│   │   │       ├── rate_limit_checker.py
│   │   │       ├── auth_bypass.py
│   │   │       ├── business_logic.py
│   │   │       ├── race_condition.py
│   │   │       ├── deserialization_checker.py   # Java/PHP/Python/.NET
│   │   │       ├── bfla_bola_checker.py         # API auth bypass
│   │   │       ├── mass_assignment_checker.py
│   │   │       ├── cache_poisoning_checker.py
│   │   │       ├── graphql_deep_scanner.py
│   │   │       ├── http_smuggling_prober.py
│   │   │       ├── prototype_pollution_checker.py
│   │   │       ├── websocket_checker.py
│   │   │       ├── info_disclosure_checker.py
│   │   │       ├── sensitive_url_finder.py
│   │   │       ├── js_analyzer.py
│   │   │       ├── api_endpoint_tester.py
│   │   │       ├── header_checker.py
│   │   │       ├── http_method_checker.py
│   │   │       ├── cookie_checker.py
│   │   │       ├── tech_cve_checker.py
│   │   │       ├── open_redirect_checker.py
│   │   │       ├── cors_checker.py
│   │   │       ├── subdomain_takeover.py
│   │   │       ├── jwt_checker.py            # JWT deep security (v2.3)
│   │   │       ├── fourxx_bypass.py         # 403/401 bypass engine (v2.4)
│   │   │       ├── cicd_checker.py          # CI/CD pipeline security (v2.7.4)
│   │   │       └── http2_http3_checker.py   # HTTP/2 & HTTP/3 testing (v2.7.4)
│   │   │
│   │   ├── exploit/                     # Exploit Araçları
│   │   │   ├── __init__.py
│   │   │   ├── metasploit_wrapper.py
│   │   │   ├── searchsploit_wrapper.py
│   │   │   ├── payload_generator.py
│   │   │   ├── reverse_shell.py
│   │   │   ├── file_upload_bypass.py
│   │   │   ├── poc_generator.py         # PoC oluşturucu
│   │   │   ├── poc_executor.py          # Sandboxed PoC execution + refinement (v2.5)
│   │   │   └── exploit_verifier.py      # Central exploit verification engine (v2.5)
│   │   │
│   │   ├── network/                     # Ağ Araçları
│   │   │   ├── __init__.py
│   │   │   ├── wireshark_wrapper.py
│   │   │   ├── netcat_wrapper.py
│   │   │   ├── enum4linux.py
│   │   │   ├── smbclient_wrapper.py
│   │   │   ├── snmpwalk_wrapper.py
│   │   │   ├── ldap_search.py
│   │   │   └── ssh_audit.py
│   │   │
│   │   ├── api_tools/                   # API Güvenlik Araçları
│   │   │   ├── __init__.py
│   │   │   ├── postman_wrapper.py
│   │   │   ├── swagger_parser.py
│   │   │   ├── graphql_introspection.py
│   │   │   ├── api_fuzzer.py
│   │   │   ├── jwt_analyzer.py
│   │   │   ├── oauth_tester.py
│   │   │   └── rest_analyzer.py
│   │   │
│   │   ├── fuzzing/                     # Fuzzing Araçları
│   │   │   ├── __init__.py
│   │   │   ├── ffuf_wrapper.py
│   │   │   ├── gobuster_wrapper.py
│   │   │   ├── dirb_wrapper.py
│   │   │   ├── feroxbuster_wrapper.py
│   │   │   ├── wfuzz_wrapper.py
│   │   │   ├── wordlist_manager.py
│   │   │   └── dynamic_wordlist.py       # Target-specific wordlist gen (v2.4)
│   │   │
│   │   ├── crypto/                      # Kriptografi Araçları
│   │   │   ├── __init__.py
│   │   │   ├── sslscan_wrapper.py
│   │   │   └── sslyze_wrapper.py
│   │   │
│   │   └── proxy/                       # Proxy Araçları
│   │       ├── __init__.py
│   │       ├── mitmproxy_wrapper.py
│   │       └── zaproxy_wrapper.py
│   │
│   ├── analysis/                        # Analiz Motoru
│   │   ├── __init__.py
│   │   ├── vulnerability_analyzer.py    # Ana zafiyet analizcisi
│   │   ├── attack_surface.py            # Saldırı yüzeyi haritalama
│   │   ├── threat_model.py              # Tehdit modelleme
│   │   ├── severity_calculator.py       # CVSS hesaplama
│   │   ├── impact_assessor.py           # Etki değerlendirme
│   │   ├── correlation_engine.py        # Bulgu korelasyonu
│   │   ├── output_aggregator.py         # Çoklu araç sonuç birleştirme ve dedup
│   │   ├── benchmark.py                 # Scan benchmarking framework (v2.4)
│   │   ├── benchmark_lab.py             # Benchmark lab TPR/FPR engine (v3.3)
│   │   ├── diff_engine.py               # Two-scan diff comparison (v2.4)
│   │   ├── global_finding_store.py      # Cross-scan finding dedup (v2.7.7)
│   │   ├── scan_profiler.py             # Performance instrumentation (v2.7.7)
│   │   └── scan_quality_report.py       # Per-scan quality assessment (v3.3.2)
│   │
│   ├── fp_engine/                       # False Positive Eleme Motoru
│   │   ├── __init__.py
│   │   ├── fp_detector.py               # Ana FP tespit motoru
│   │   ├── evidence_quality_gate.py     # Kanıt kalite kapısı (v3.3)
│   │   ├── verification/                # Doğrulama stratejileri
│   │   │   ├── __init__.py
│   │   │   ├── multi_tool_verify.py     # Çoklu araç doğrulaması
│   │   │   ├── context_verify.py        # Bağlam doğrulaması
│   │   │   ├── manual_verify.py         # Manuel doğrulama rehberi
│   │   │   ├── response_diff.py         # Response karşılaştırma
│   │   │   └── payload_confirm.py       # Payload doğrulama
│   │   ├── scoring/                     # Güven puanlama
│   │   │   ├── __init__.py
│   │   │   ├── confidence_scorer.py     # Güven skoru hesaplama
│   │   │   ├── evidence_chain.py        # Kanıt zinciri oluşturma
│   │   │   └── bayesian_filter.py       # Bayes filtresi
│   │   ├── patterns/                    # Bilinen FP kalıpları
│   │   │   ├── __init__.py
│   │   │   ├── known_fps.py             # Bilinen false positive'ler
│   │   │   ├── tool_quirks.py           # Araç spesifik FP'ler
│   │   │   └── waf_artifacts.py         # WAF kaynaklı FP'ler  
│   │   └── learning/                    # Öğrenme sistemi
│   │       ├── __init__.py
│   │       ├── fp_feedback.py           # Geri bildirim döngüsü
│   │       └── pattern_learner.py       # Yeni FP kalıpları öğrenme
│   │
│   ├── reporting/                       # Raporlama Sistemi
│   │   ├── __init__.py
│   │   ├── report_generator.py          # Ana rapor oluşturucu
│   │   ├── templates/                   # Rapor şablonları
│   │   │   ├── __init__.py
│   │   │   ├── hackerone_template.py
│   │   │   ├── bugcrowd_template.py
│   │   │   ├── generic_template.py
│   │   │   ├── executive_summary.py
│   │   │   └── technical_detail.py
│   │   ├── formatters/                  # Çıktı formatları
│   │   │   ├── __init__.py
│   │   │   ├── markdown_formatter.py
│   │   │   ├── html_formatter.py
│   │   │   ├── pdf_formatter.py
│   │   │   └── json_formatter.py
│   │   ├── evidence/                    # Kanıt yönetimi
│   │   │   ├── __init__.py
│   │   │   ├── screenshot.py            # Ekran görüntüsü
│   │   │   ├── request_logger.py        # HTTP istek/yanıt loglama
│   │   │   ├── poc_recorder.py          # PoC kayıt
│   │   │   ├── timeline.py              # Zaman çizelgesi
│   │   │   └── evidence_aggregator.py   # Unified evidence package builder (v2.5)
│   │   ├── auto_draft.py               # Per-finding draft report generator (v2.7.7)
│   │   └── platform_submit/             # Platform gönderimi
│   │       ├── __init__.py
│   │       ├── hackerone_api.py
│   │       ├── bugcrowd_api.py
│   │       └── generic_api.py
│   │
│   ├── integrations/                    # Dış Entegrasyonlar
│   │   ├── __init__.py
│   │   ├── notification.py              # Bildirim sistemi (Slack, Discord, Telegram)
│   │   ├── database.py                  # Veritabanı yönetimi (SQLite/PostgreSQL)
│   │   ├── cache.py                     # Önbellek (Redis)
│   │   ├── queue.py                     # Görev kuyruğu (Celery/RQ)
│   │   ├── asset_db.py                  # Asset tracking database (v2.4)
│   │   └── diff_alerts.py               # Diff-based notification alerts (v2.4)
│   │
│   ├── platforms/                       # Bug Bounty Platform Adaptörleri
│   │   ├── __init__.py
│   │   ├── hackerone_programs.py         # HackerOne program discovery
│   │   ├── bugcrowd_programs.py         # Bugcrowd program discovery
│   │   ├── intigriti_programs.py        # Intigriti program discovery
│   │   └── program_manager.py           # Multi-platform program yönetimi
│   │
│   ├── gui/                             # GUI Arayüzü (PySide6)
│   │   ├── __init__.py
│   │   ├── app.py                       # QApplication başlatıcı
│   │   ├── main_window.py               # Ana pencere
│   │   ├── styles/                      # QSS tema dosyaları
│   │   └── widgets/                     # GUI bileşenleri
│   │       ├── dashboard.py             # Ana dashboard istatistik
│   │       ├── findings_panel.py        # Bulgu tablosu ve detay
│   │       ├── log_viewer.py            # Çoklu log kaynağı viewer
│   │       ├── process_viewer.py        # Araç çalıştırma izleyici
│   │       ├── program_browser.py       # Platform program gezgini
│   │       ├── scan_control.py          # Tarama başlat/durdur
│   │       └── settings_panel.py        # Konfigürasyon düzenleyici
│   │
│   ├── file_manager/                    # Çıktı dosya organizasyonu
│   │   ├── __init__.py
│   │   └── output_organizer.py
│   │
│   └── utils/                           # Yardımcı Modüller
│       ├── __init__.py
│       ├── logger.py                    # Multi-sink yapılandırılmış loglama (v2)
│       ├── dev_diagnostics.py           # Geliştirme tanılama & sağlık kontrolü
│       ├── json_utils.py                # Paylaşılan LLM JSON çıktı ayrıştırıcı (v2.2)
│       ├── rate_limiter.py              # Rate limiting
│       ├── scope_validator.py           # Scope doğrulama
│       ├── sanitizer.py                 # Input/output sanitizasyonu
│       ├── network_utils.py             # Ağ yardımcıları
│       ├── crypto_utils.py              # Kriptografi yardımcıları
│       ├── file_utils.py                # Dosya işlemleri
│       ├── param_intelligence.py        # Parameter attack-type classification (v3.4)
│       └── constants.py                 # Sabitler
│
├── data/
│   ├── wordlists/                       # Özel wordlist'ler
│   │   ├── directories.txt
│   │   ├── subdomains.txt
│   │   ├── parameters.txt
│   │   ├── passwords.txt
│   │   └── payloads/
│   │       ├── xss.txt                  # 759 payload (v2.3: mXSS, DOMPurify, CSP bypass)
│   │       ├── sqli.txt                 # 426 payload (v2.3: second-order, OOB, JSON/GraphQL)
│   │       ├── lfi.txt                  # 425 payload
│   │       ├── ssrf.txt                 # 325 payload (v2.3: K8s/Docker, DNS rebinding)
│   │       ├── rce.txt                  # 357 payload
│   │       ├── ssti.txt                 # 297 payload
│   │       ├── open_redirect.txt        # 286 payload
│   │       ├── xxe.txt                  # 270 payload
│   │       ├── nosqli.txt              # 222 payload
│   │       ├── header_injection.txt     # 218 payload
│   │       ├── jwt.txt                  # 25 payload (v2.3: alg:none, kid injection)
│   │       ├── deserialization.txt      # 19 payload (v2.3: Java/PHP/Python/.NET)
│   │       ├── prototype_pollution.txt  # 21 payload (v2.3: __proto__, constructor)
│   │       └── graphql.txt              # 19 payload (v2.3: introspection, batch) (Toplam: 3,669)
│   ├── nuclei_templates/                # Özel Nuclei template'leri
│   │   ├── custom/
│   │   └── community/
│   ├── known_infrastructure_ips.json    # CDN/WAF/DNS infra IP database (v3.3)
│   ├── benchmark/                       # Benchmark lab manifests & results (v3.3)
│   │   └── manifests.json               # 7-lab expected findings manifest
│   ├── fingerprints/                    # Teknoloji parmak izleri
│   └── known_vulns/                     # Bilinen zafiyet veritabanı
│
├── models/                              # Yerel model dosyaları
│   ├── README.md                        # Model indirme talimatları
│   └── .gitkeep
│
├── output/                              # Tarama çıktıları
│   ├── reports/                         # Oluşturulan raporlar
│   ├── screenshots/                     # Ekran görüntüleri
│   ├── evidence/                        # Kanıt dosyaları
│   └── logs/                            # Çalışma logları
│
├── tests/                               # Test Suite (~2663 test, 10+ alt dizin)
│   ├── __init__.py
│   ├── conftest.py
│   ├── regression/                      # Versiyon bazlı regresyon testleri (33 dosya)
│   │   ├── __init__.py
│   │   ├── test_deep_audit_fixes.py     # Deep audit düzeltme testleri (v1/v2/v3)
│   │   ├── test_v5_p0_regression.py     # v5 Phase 0-6 regresyon testleri
│   │   ├── test_v7_modules.py           # v7 modül testleri
│   │   ├── test_v11_modules.py          # v11 modül testleri
│   │   ├── test_v17_production_fixes.py # v17 üretim düzeltmeleri
│   │   ├── test_v18_url_list_fixes.py   # URL-as-list cascade düzeltmeleri
│   │   ├── test_v19_type_safety_hardening.py  # Tip güvenliği testleri
│   │   ├── test_v20_serialization_robustness.py # Serialization güvenliği
│   │   ├── test_v21_production_quality.py     # Üretim kalite testleri
│   │   ├── test_v22_type_safety_audit.py      # Tip güvenliği denetimi
│   │   ├── test_v23_dead_module_wiring.py     # Ölü modül bağlantı testleri
│   │   ├── test_v24_fp_engine_deep_wiring.py  # FP engine derin bağlantı
│   │   ├── test_v25_audit_fixes.py      # v25 denetim düzeltmeleri
│   │   ├── test_v26_scan_quality_fixes.py     # Tarama kalite düzeltmeleri
│   │   ├── test_v280_regression.py      # v2.8.0 regresyon testleri
│   │   └── ...                          # + diğer versiyon regresyon testleri
│   ├── test_analysis/                   # Analiz modülü testleri (7 dosya)
│   ├── test_brain/                      # Brain engine testleri (4 dosya)
│   ├── test_fp_engine/                  # FP engine testleri (7 dosya)
│   ├── test_gui/                        # GUI testleri (1 dosya)
│   ├── test_integration/                # Entegrasyon testleri (6 dosya)
│   ├── test_reporting/                  # Raporlama testleri (2 dosya)
│   ├── test_tools/                      # Araç testleri (13 dosya)
│   ├── test_utils/                      # Yardımcı modül testleri (4 dosya)
│   └── test_workflow/                   # İş akışı testleri (7 dosya)
│
├── scripts/                             # Yardımcı scriptler (aktif)
│   ├── setup_kali_tools.sh              # Kali araçları kurulum
│   ├── setup_go_tools.sh                # Go tabanlı araç kurulumu
│   ├── download_models.sh               # Model indirme
│   ├── setup_wordlists.sh               # Wordlist indirme
│   ├── health_check.sh                  # Sistem sağlık kontrolü
│   ├── ssh_tunnel.sh                    # SSH tunnel yönetimi (brain bağlantısı)
│   ├── lmstudio_remote.sh              # LM Studio uzak bağlantı
│   ├── benchmark_runner.py              # Benchmark lab CLI runner (v3.3)
│   ├── e2e_test.py                      # End-to-end test scripti
│   ├── generate_payloads.py             # Payload üreteci
│   ├── launch_gui.py                    # GUI başlatıcı
│   ├── launch_gui.sh                    # GUI shell başlatıcı
│   ├── test_api_keys.py                 # API key doğrulama
│   ├── test_hackerone.py                # HackerOne API testi
│   └── archive/                         # Arşivlenmiş eski scriptler (15 dosya)
│       ├── benchmark_runner_old.py      # Eski benchmark runner
│       ├── fix_*.py                     # Tek seferlik düzeltme scriptleri (7 dosya)
│       └── update_*.py                  # Tek seferlik güncelleme scriptleri (7 dosya)
│
├── docker/
│   ├── Dockerfile                       # Ana container
│   ├── Dockerfile.gpu                   # GPU destekli container
│   ├── docker-compose.yaml              # Tam stack
│   └── benchmark-lab.yaml               # 7 vulnerable-by-design lab (v2.7.4)
│
├── docs/                                # Dokümantasyon (aktif referanslar kökde)
│   ├── ARCHITECTURE.md                  # Detaylı mimari dokümantasyon
│   ├── TOOL_CATALOG.md                  # Araç katalogu
│   ├── WORKFLOW_GUIDE.md                # İş akışı rehberi
│   ├── API_REFERENCE.md                 # API referansı
│   ├── CONTRIBUTING.md                  # Katkı rehberi
│   ├── LLM_RESEARCH_REPORT.md           # LLM model araştırma raporu
│   ├── plans/                           # Geliştirme planları (15 dosya)
│   │   ├── NEXT_LEVEL_PLAN.md           # İlk plan
│   │   ├── NEXT_LEVEL_PLAN_V2.md        # ...
│   │   └── NEXT_LEVEL_PLAN_V25.md       # En güncel plan
│   ├── audits/                          # Kod denetim raporları (7 dosya)
│   │   ├── BRAIN_INTELLIGENCE_AUDIT.md
│   │   ├── CODE_AUDIT_BRAIN_WORKFLOW.md
│   │   ├── CRASH_RISK_AUDIT_REPORT.md
│   │   ├── DEEP_AUDIT_TOOLS_FP_ENGINE.md
│   │   ├── FINDING_AUDIT_REPORT.md
│   │   ├── TOOLS_CODE_AUDIT.md
│   │   └── COMPETITIVE_GAP_ANALYSIS.md
│   └── archive/                         # Arşivlenmiş eski belgeler
│       └── bugbounty_bot_ultimate_prompt_v5.md
│
├── pyproject.toml                       # Proje metadata ve bağımlılıklar
├── requirements.txt                     # Python bağımlılıkları
├── Makefile                             # Yaygın komutlar
├── .env.example                         # Ortam değişkenleri şablonu
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🔄 İŞ AKIŞI (WORKFLOW) DETAYI

### Ana Çalışma Döngüsü

Bot aşağıdaki ana aşamalardan geçerek çalışır. Her aşama kendi içinde alt görevlere bölünür:

```
[1. SCOPE ANALYSIS] → [2. PASSIVE RECON] → [3. ACTIVE RECON] → [4. ENUMERATION]
        ↓                                                              ↓
[8. REPORTING]  ← [7. FP ELIMINATION] ← [6. VULNERABILITY SCAN] ← [5. ATTACK SURFACE MAP]
        ↓
[9. PLATFORM SUBMIT] → [10. KNOWLEDGE UPDATE]
```

### Aşama 1: SCOPE ANALİZİ (Brain: Secondary - BaronLLM v2 /no_think)
```yaml
Görev: Hedef scope'u analiz et ve sınırları belirle
Girdiler:
  - Hedef domain/IP/URL listesi
  - Bug bounty programı kuralları
  - Scope dahil/hariç listesi
Çıktılar:
  - Doğrulanmış hedef listesi
  - Out-of-scope filtreleri
  - Tarama stratejisi önerisi
Araçlar: whois, dig, scope_validator
Karar Noktası: Scope uygun mu? → İnsan onayı (yarı-otonom modda)
```

### Aşama 2: PASİF KEŞİF (Brain: Secondary - BaronLLM v2 /no_think)
```yaml
Görev: Hedef hakkında pasif bilgi toplama (hedefe dokunmadan)
Alt Görevler:
  2.1 Subdomain Enumeration:
    - subfinder → hızlı subdomain keşfi
    - amass (passive) → kapsamlı pasif keşif
    - crt.sh → sertifika transparency logları
    - assetfinder → varlık keşfi
    - findomain → hızlı subdomain bulma
    → aggregator ile sonuçları birleştir, duplikatları temizle
    
  2.2 OSINT Toplama:
    - theHarvester → email, subdomain, host keşfi
    - shodan → internet bağlı cihaz keşfi
    - censys → sertifika ve host bilgileri
    - whois → domain kayıt bilgileri
    - Google dorking → hassas bilgi arama
    - GitHub dorking → kaynak kod sızıntıları
    
  2.3 DNS Analizi:
    - dnsrecon → DNS kayıt keşfi
    - dnsx → DNS çözümleme ve doğrulama
    - zone transfer denemesi
    
  2.4 Wayback/Archive:
    - waybackurls → geçmiş URL'ler
    - gau → tüm bilinen URL'ler 
    
Çıktılar:
  - Keşfedilen subdomain'ler
  - Açık portlar ve servisler (Shodan'dan)
  - Email adresleri, teknoloji bilgileri
  - Potansiyel hassas bilgi sızıntıları
Karar: Scope validator ile tüm keşifleri filtrele
```

### Aşama 3: AKTİF KEŞİF (Brain: Secondary - BaronLLM v2 /no_think)
```yaml
Görev: Hedefe aktif olarak dokunarak bilgi toplama
Alt Görevler:
  3.1 Canlılık Kontrolü:
    - httpx → HTTP probe, durum kodu, başlıklar
    - port tarama stratejisi belirleme
    
  3.2 Port Tarama:
    - rustscan/masscan → hızlı port keşfi (top 1000)
    - nmap → detaylı servis ve versiyon tespiti
    - service_detector → servis parmak izi
    
  3.3 Web Keşfi:
    - katana → modern web crawler
    - gospider → hızlı web spider
    - hakrawler → yüzey crawling
    - eyewitness/aquatone → görsel keşif (screenshot)
    
  3.4 Teknoloji Tespiti:
    - whatweb → web teknoloji tespiti
    - wappalyzer → framework/CMS tespiti
    - fingerprinter → özel parmak izi eşleme
    
  3.5 Directory/File Brute Force:
    - ffuf → hızlı fuzzing
    - feroxbuster → recursive content discovery
    - gobuster → directory brute force
    
Çıktılar:
  - Canlı host listesi
  - Port/servis haritası
  - Web uygulaması haritası
  - Teknoloji stack bilgileri
  - Keşfedilen endpoint'ler
Rate Limiting: scope_validator + rate_limiter kontrol altında
```

### Aşama 4: ENUMERATION (Brain: Primary - BaronLLM v2)
```yaml
Görev: Derinlemesine sayım ve analiz
Alt Görevler:
  4.1 Web Uygulama Enumeration:
    - Parametre keşfi (arjun, paramspider)
    - JavaScript analizi (endpoints, secrets)
    - API endpoint keşfi (swagger, openapi)
    - GraphQL introspection
    - Form ve input noktaları haritalama
    
  4.2 Authentication Analizi:
    - Login mekanizması analizi
    - OAuth/SAML flow analizi
    - JWT token analizi
    - Session yönetimi analizi
    - Cookie güvenliği
    
  4.3 Network Enumeration:
    - SMB enumeration (enum4linux)
    - SNMP enumeration
    - LDAP sorguları
    - SSH audit
    
  4.4 SSL/TLS Analizi:
    - testssl → kapsamlı SSL/TLS kontrol
    - ssl_scan → cipher suite analizi
    
Çıktılar:
  - Detaylı saldırı yüzeyi haritası
  - Potansiyel zafiyet noktaları listesi
  - Endpoint + parametre matrisi
Brain Kullanımı: BaronLLM v2 (PRIMARY, CoT aktif) ile derin analiz, korelasyon ve strateji belirleme
```

### Aşama 5: SALDIRI YÜZEYİ HARİTALAMA (Brain: Primary - BaronLLM v2)
```yaml
Görev: Tüm keşif verilerini birleştirip saldırı stratejisi oluştur
İşlem:
  - attack_surface.py → tüm endpoint'leri saldırı yüzeyine dönüştür
  - threat_model.py → her endpoint için tehdit modelleme
  - Brain (BaronLLM v2) → en yüksek ROI saldırı vektörlerini önceliklendir
  - risk_assessor.py → risk skoru hesapla
Çıktılar:
  - Önceliklendirilmiş saldırı planı
  - Her hedef için uygulanacak test listesi
Karar Noktası: Saldırı planı onayı (yarı-otonom modda insan onayı)
```

### Aşama 6: ZAFİYET TARAMASI (Brain: Dual - görev bazlı)
```yaml
Görev: Sistematik zafiyet taraması
Alt Görevler:
  6.1 Otomatik Tarama:
    - nuclei → template bazlı kapsamlı tarama
    - nikto → web sunucu zafiyetleri
    - wpscan → WordPress zafiyetleri (CMS ise)
    
  6.2 Injection Testleri:
    - sqlmap → SQL injection (GET/POST/Cookie/Header)
    - commix → command injection
    - nosqlmap → NoSQL injection
    - tplmap → template injection (SSTI)
    
  6.3 XSS Testleri:
    - dalfox → DOM/Reflected/Stored XSS
    - xsstrike → akıllı XSS tespiti
    
  6.4 SSRF/Open Redirect:
    - ssrfmap → SSRF tespiti
    - openredirex → open redirect tespiti
    
  6.5 Diğer Testler:
    - crlfuzz → CRLF injection
    - corsy → CORS misconfiguration
    - smuggler → HTTP request smuggling
    - jwt_tool → JWT zafiyetleri
    
  6.6 Özel Mantık Testleri (Brain: BaronLLM v2) — 27 Denetleyici:
    - IDOR checker → yetkilendirme bypass
    - Auth bypass → kimlik doğrulama atlatma
    - Business logic → iş mantığı hataları
    - Race condition → yarış durumu
    - Rate limit bypass
    - Deserialization → Java/PHP/Python/.NET deserialization
    - BFLA/BOLA → API function/object-level authorization bypass
    - Mass assignment → unauthorized field writing
    - Cache poisoning → web cache poisoning
    - GraphQL deep → introspection, alias brute force, batch, field/mutation bruteforce, APQ bypass
    - HTTP smuggling → CL.TE, TE.CL, TE.TE
    - Prototype pollution → JavaScript prototype chain manipulation
    - WebSocket → CSWSH, message injection
    - Info disclosure → sensitive information exposure
    - Sensitive URL finder → admin panels, backup files
    - JS analyzer → endpoint/secret extraction, entropy secrets, DOM XSS source/sink
    - API endpoint tester → REST/GraphQL endpoint security
    - Header checker → security header analysis
    - HTTP method checker → method override, TRACE/OPTIONS
    - Cookie checker → HttpOnly, Secure, SameSite
    - Tech CVE checker → technology-specific CVE matching
    - Open redirect checker
    - CORS checker → misconfiguration detection
    - Subdomain takeover → dangling DNS records
    - JWT deep checker → alg:none, weak secret, kid injection, claim tampering (v2.3)
    - CI/CD checker → Jenkins, GitLab, dep confusion, build log secrets (v2.7.4)
    - HTTP/2 & HTTP/3 checker → ALPN, H2C smuggling, Alt-Svc, CONNECT tunneling (v2.7.4)
    
Çıktılar:
  - Ham zafiyet bulguları (unfiltered)
  - Araç bazlı sonuçlar
Brain Kullanımı: SECONDARY (/no_think) → araç seçimi/parametreleme, PRIMARY (CoT) → özel mantık testleri
```

### Aşama 7: FALSE POSİTİVE ELEMESİ (Brain: Primary - BaronLLM v2) ⚡ KRİTİK
```yaml
Görev: Tüm bulguları doğrula, FP'leri ayıkla
Strateji (7 Katmanlı Doğrulama):

  Katman 1 - Bilinen FP Kalıp Eşleme:
    - known_fps.py → bilinen false positive kalıplarıyla karşılaştır
    - tool_quirks.py → araç spesifik FP kalıpları
    - waf_artifacts.py → WAF/CDN kaynaklı sahte bulgular
    
  Katman 2 - Çoklu Araç Doğrulama:
    - multi_tool_verify.py → aynı zafiyeti farklı araçla doğrula
    - En az 2 farklı araç aynı bulguyu desteklemeli
    - Araç1 XSS buldu → Araç2 ile doğrula → Brain ile analiz et
    
  Katman 3 - Bağlam Analizi (Brain: BaronLLM v2):
    - context_verify.py → HTTP istek/yanıt bağlamını analiz et
    - response_diff.py → normal vs payload'lı yanıt karşılaştırması
    - Payload gerçekten execute oldu mu?
    - Yanıt kodu ve içeriği beklenenle uyuşuyor mu?
    
  Katman 4 - Payload Doğrulama:
    - payload_confirm.py → payload'ın gerçekten çalıştığını doğrula
    - Blind test: farklı payload varyasyonları ile tekrar test
    - Time-based doğrulama (SQLi, XXE vb. için)
    - Out-of-band doğrulama (SSRF, XXE için)
    
  Katman 5 - Güven Puanlama:
    - confidence_scorer.py → 0-100 güven skoru (FPDetector'a entegre)
    - evidence_chain.py → kanıt zinciri oluştur (pipeline'a bağlı)
    - bayesian_filter.py → Bayes olasılık hesabı
    
  Katman 6 - Pipeline Entegrasyonları (v2.1→v2.2):
    - SearchSploit gürültü filtresi (severity cap MEDIUM + unverified flag)
    - İki-aşamalı deduplication (same-tool + cross-tool)
    - Evidence chain construction (kriptografik hash'li kanıt zinciri)
    - Brain-powered deep verification (LLM ile bulgu doğrulama)
    - ConfidenceScorer → FPDetector entegrasyonu (30+ faktörlü puanlama)
    - (v2.2) Asimetrik confidence merge: brain yükseltme=60/40, düşürme=30/70
    - (v2.2) Brain-generated endpoint scope validation (hallüsinasyon filtresi)
    - (v2.2) FP prompt'ları İngilizce + 3 few-shot kalibrasyon örneği
    - (v2.2) Payload safety filter (yıkıcı komut engelleme)
    - (v2.2) Brain response cache (tekrarlayan prompt atlanır)
    - (v2.2) Central brain-down flag (3 ardışık hata → brain bypass)
    
  Katman 7 - Re-request Doğrulama (v2.3):
    - fp_detector._layer6_rerequest_verify() → orijinal isteği tekrar gönder
    - Query parametresiz kontrol isteği ile karşılaştır
    - Status code + body length diff analizi
    - Reproduced → +10, partial → +3/+5, not reproduced → -8
    - Sadece MEDIUM+ severity bulgular için aktif
    
  Katman 8 - Cross-Finding LLM Reasoning (v2.3):
    - correlation_engine.detect_chains_llm() → LLM ile bulgu korelasyonu
    - 9 KNOWN_CHAINS ötesinde yeni saldırı zincirleri keşfeder
    - Rule-based + LLM hibrit yaklaşım
    
  Güven Skoru Eşikleri:
    - 90-100: Kesin zafiyet → Otomatik raporlama
    - 70-89:  Yüksek olasılık → Minimal doğrulama sonrası rapor
    - 50-69:  Orta olasılık → İnsan onayı gerekli
    - 30-49:  Düşük olasılık → Derin analiz veya red
    - 0-29:   Büyük olasılıkla FP → Sessiz log, skip
    
Çıktılar:
  - Doğrulanmış zafiyet listesi + güven skoru
  - Her bulgu için kanıt zinciri
  - FP olarak etiketlenen bulgular (öğrenme için sakla)
```

### Aşama 8: RAPORLAMA (Brain: Primary - BaronLLM v2)
```yaml
Görev: Profesyonel bug bounty raporu oluştur
İçerik:
  - Başlık: Kısa, açıklayıcı, etkileyici
  - Özet: 2-3 cümlelik zafiyet açıklaması
  - Severity: CVSS v3.1 skoru + açıklama
  - Etki Analizi: İş etkisi, veri etkisi, teknik etki
  - Adım Adım Reproduksiyon:
    1. Prereqs
    2. Her adım detaylı (URL, parametre, değer)
    3. Ekran görüntüleri
    4. PoC kodu/komutu
  - HTTP İstek/Yanıt Örnekleri
  - Önerilen Düzeltme
  - Referanslar (CWE, OWASP, CVE)
  
Platform Uyumluluğu:
  - HackerOne formatı
  - Bugcrowd formatı
  - Genel format
  
Çıktılar:
  - Markdown rapor
  - HTML rapor
  - JSON veri (API entegrasyonu için)
  - PDF rapor (opsiyonel)
Brain Kullanımı: BaronLLM v2 (PRIMARY, CoT aktif) ile profesyonel, ikna edici rapor yazma
```

### Aşama 9: PLATFORM GÖNDERİMİ (Brain: ihtiyaç yok)
```yaml
Görev: Raporu uygun platforma gönder
Modlar:
  - Tam Otonom: Güven skoru >90 → otomatik gönder
  - Yarı Otonom: Her rapor gönderiminde insan onayı
  - Draft Mod: Sadece draft olarak kaydet
API Entegrasyonları:
  - HackerOne API v1
  - Bugcrowd API
  - Intigriti API
Karar Noktası: Gönderim onayı (hibrit modda)
```

### Aşama 10: BİLGİ GÜNCELLEME (Brain: Secondary - BaronLLM v2 /no_think)
```yaml
Görev: Öğrenilen bilgileri kaydet
- Yeni FP kalıplarını kaydet
- Başarılı saldırı vektörlerini kaydet
- Teknoloji-zafiyet korelasyonlarını güncelle
- Performans metriklerini logla
```

---

## 🧠 BRAIN ENGINE DETAYLARI

### Model Yükleme ve Yönetim

```python
# Temel model konfigürasyonu
PRIMARY_MODEL:
  name: "BaronLLM-v2-OffensiveSecurity"
  file: "baronllm-v2-offensivesecurity-q8_0.gguf"
  source: "AlicanKiraz0/BaronLLM-v2-OffensiveSecurity-GGUF"
  base: "Qwen3-14B"
  context_length: 32768
  gpu_layers: -1  # Tüm katmanları GPU'ya yükle (varsa)
  threads: 8
  temperature: 0.1  # Düşük — deterministic analiz için
  top_p: 0.9
  repeat_penalty: 1.1
  use_for:
    - deep_analysis
    - exploit_strategy
    - fp_elimination
    - report_writing
    - business_logic_testing
    - complex_reasoning
    - strategic_planning

SECONDARY_MODEL:
  name: "BaronLLM-v2-OffensiveSecurity (/no_think)"
  file: "baronllm-v2-offensivesecurity-q8_0.gguf"  # Aynı model, CoT devre dışı
  base: "Qwen3-14B"
  context_length: 32768
  gpu_layers: -1
  threads: 8
  temperature: 0.2
  top_p: 0.95
  repeat_penalty: 1.05
  use_for:
    - fast_triage
    - recon_decisions
    - tool_selection
    - scope_analysis
    - parallel_analysis
    - quick_assessment

FALLBACK_MODEL:
  name: "DeepHat-V1-7B"
  file: "deephat-v1-7b-q4_k_m.gguf"
  source: "Neanderthal/DeepHat-V1-7B-GGUF"
  base: "Qwen2.5-Coder-7B"
  context_length: 8192
  gpu_layers: -1
  threads: 4
  temperature: 0.3
  top_p: 0.9
  repeat_penalty: 1.1
  use_for:
    - emergency_fallback
    - fast_triage
    - tool_selection
```

### Brain Router Mantığı

```python
# Görev karmaşıklığına göre otomatik model seçimi
ROUTING_RULES:
  # Basit, hızlı görevler → BaronLLM v2 /no_think (Secondary)
  - pattern: "recon|enumerate|scan_config|tool_select|triage"
    brain: secondary
    reason: "Hızlı karar, düşük latency gerekli (CoT devre dışı)"
    
  # Karmaşık analiz görevleri → BaronLLM v2 /think (Primary)
  - pattern: "analyze|exploit|fp_check|report|reason|strategy"
    brain: primary
    reason: "Derin analiz, yüksek doğruluk gerekli (CoT aktif)"
    
  # Çift model kullanımı (ensemble)
  - pattern: "critical_decision|final_verification"
    brain: both
    reason: "Her iki modelin de onayı gerekli"
    strategy: "majority_vote"  # veya "consensus"
```

### Prompt Engineering Stratejisi

Her görev türü için özelleştirilmiş system prompt'lar kullanılır:

```
RECON_SYSTEM_PROMPT:
  "Sen uzman bir bug bounty hunter'ın keşif aşamasındasın.
   Görevin: verilen hedef hakkında toplanan bilgileri analiz et.
   Kurallar:
   - Scope dışına ASLA çıkma
   - Her keşfi öncelik sırasına göre değerlendir
   - Saldırı yüzeyini genişletecek ipuçlarına odaklan
   - JSON formatında yapılandırılmış yanıt ver"

FP_ELIMINATION_PROMPT:
  "Sen siber güvenlik uzmanı bir analistsin.
   Görevin: verilen zafiyet bulgusunun GERÇEK mi yoksa FALSE POSITIVE mi olduğunu belirle.
   Analiz Et:
   1. HTTP istek ve yanıtı incele
   2. Payload'ın gerçekten execute olup olmadığını kontrol et
   3. Bağlamı değerlendir (WAF, CDN, load balancer etkileri)
   4. Benzer bilinen FP kalıplarıyla karşılaştır
   5. 0-100 arası güven skoru ver
   Yanıt: {verdict, confidence, reasoning, evidence}"

REPORT_WRITING_PROMPT:
  "Sen deneyimli bir bug bounty hunter'sın ve profesyonel rapor yazıyorsun.
   Hedef platform: {platform}
   Rapor tarzı: Net, teknik, ikna edici, reproduksiyon adımları açık
   CVSS skorunu hesapla ve gerekçelendir.
   Etki analizini iş perspektifinden yaz.
   Düzeltme önerisini actionable yap."
```

---

## 🛡️ FALSE POSİTİVE ELİMİNASYON DERİN DETAY

Bu, botun EN KRİTİK modülüdür. Bir profesyonel bug bounty hunter'ı amatörden ayıran en önemli özellik, gerçek zafiyetleri false positive'lerden ayırabilme yeteneğidir.

### FP Tespit Stratejileri

#### 1. Tool-Specific FP Patterns Database
```yaml
nuclei_known_fps:
  - pattern: "tech-detect/*"
    action: "info_only"  # Zafiyet değil, bilgi
  - pattern: "ssl/deprecated-tls"
    verify: "testssl ile doğrula"
    common_fp_reason: "CDN/proxy TLS terminasyonu"

sqlmap_known_fps:
  - pattern: "boolean-based blind"
    confidence_penalty: -20
    verify: "time-based ile çapraz doğrula"
  - pattern: "UNION query"
    verify: "extraction yapılabiliyor mu kontrol et"
    
xss_known_fps:
  - pattern: "reflected in attribute"
    verify: "encoding kontrol et, gerçekten break oluyor mu?"
  - pattern: "DOM-based"
    verify: "JavaScript console'da execute oluyor mu?"
```

#### 2. Response Differential Analysis
```
Normal_Request:  GET /search?q=test → 200, body_hash: abc123
Payload_Request: GET /search?q=<script>alert(1)</script> → 200, body_hash: def456

Analiz:
- Status code aynı mı? Evet → devam
- Body hash farklı mı? Evet → devam
- Payload body'de reflect oluyor mu? → Kontrol et
- Encoding uygulanmış mı? → &lt;script&gt; ise FP
- DOM'da execute oluyor mu? → Browser test
```

#### 3. Multi-Tool Cross-Verification Matrix
```
Zafiyet Türü    | Birincil Araç | Doğrulama Araçları          | Min Onay
----------------|---------------|-----------------------------|---------
SQLi            | sqlmap        | nuclei-sqli, manual curl    | 2/3
XSS (Reflected) | dalfox        | xsstrike, nuclei-xss        | 2/3
XSS (Stored)    | dalfox        | manual verify, browser       | 2/3 + manual
SSRF            | ssrfmap       | nuclei-ssrf, burp collab     | 2/3 + OOB
SSTI            | tplmap        | nuclei-ssti, manual          | 2/3
Command Inj     | commix        | nuclei-cmd, manual curl      | 2/3
IDOR            | custom        | manual, brain-analysis       | brain + manual
CORS            | corsy         | nuclei-cors, manual curl     | 2/3
Open Redirect   | openredirex   | nuclei-redirect, manual      | 2/3
JWT             | jwt_tool      | manual analysis              | tool + brain
```

#### 4. WAF/CDN Detection & Compensation
```yaml
waf_detection:
  methods:
    - wafw00f  # WAF fingerprinting
    - response header analysis
    - behavioral analysis (blocking patterns)
  
  compensation:
    cloudflare:
      - "cf-ray header → Cloudflare detected"
      - "403 with Cloudflare challenge → WAF block, not vuln"
      - "Payload encoded? Try bypass techniques before FP label"
    akamai:
      - "X-Akamai-* headers → Akamai detected"
      - "Reference ID in 403 → WAF block"
    aws_waf:
      - "x-amzn-RequestId → AWS WAF"
      - "Custom 403 page → WAF block"
```

#### 5. Confidence Score Algorithm
```python
def calculate_confidence(finding):
    base_score = 50  # Başlangıç
    
    # Artıran faktörler
    if finding.multi_tool_confirmed: score += 20
    if finding.payload_executed: score += 25
    if finding.response_diff_significant: score += 10
    if finding.no_waf_interference: score += 5
    if finding.brain_analysis_confirms: score += 15
    if finding.oob_callback_received: score += 30
    if finding.data_extracted: score += 25
    
    # Azaltan faktörler
    if finding.single_tool_only: score -= 15
    if finding.waf_detected: score -= 10
    if finding.known_fp_pattern_match: score -= 30
    if finding.inconsistent_results: score -= 20
    if finding.cdn_detected: score -= 5
    if finding.generic_error_page: score -= 15
    
    return max(0, min(100, score))
```

---

## 🔧 ARAÇ ENTEGRASYONU DETAYI

### Araç Baz Sınıfı (Tool Base Class)

Her araç wrapper'ı şu interface'i implement etmelidir:

```python
class SecurityTool(ABC):
    """Tüm güvenlik araçları için temel sınıf"""
    
    name: str                    # Araç adı
    category: ToolCategory       # recon/scanner/exploit/network/fuzzing/crypto/proxy
    binary_path: str             # Çalıştırılabilir dosya yolu
    version: str                 # Versiyon
    is_installed: bool           # Kurulu mu?
    requires_root: bool          # Root gerekli mi?
    risk_level: RiskLevel        # safe/low/medium/high/critical
    rate_limit: RateLimit        # İstek hız limiti
    
    @abstractmethod
    async def run(self, target, options) -> ToolResult
    
    @abstractmethod
    def parse_output(self, raw_output) -> List[Finding]
    
    @abstractmethod
    def is_available(self) -> bool
    
    @abstractmethod
    def get_default_options(self, profile: ScanProfile) -> dict
```

### Araç Çalıştırma Güvenlik Kuralları

```yaml
safety_rules:
  # ASLA yapılmaması gerekenler
  never:
    - "Scope dışı hedeflere request gönderme"
    - "DoS/DDoS testi yapma (açıkça izin verilmedikçe)"
    - "Gerçek exploit payload'ı çalıştırma (sadece PoC)"
    - "Veri silme veya değiştirme"
    - "Hesap ele geçirme (sadece doğrulama)"
    - "Spam gönderme"
    
  # Her komut öncesi kontrol
  pre_execution_checks:
    - "Hedef scope içinde mi? → scope_validator"
    - "Rate limit aşılıyor mu? → rate_limiter"
    - "Komut risk seviyesi nedir? → risk_assessor"
    - "Yüksek riskli komut → insan onayı (yarı-otonom)"
    
  # Araç çalıştırma timeout'ları
  timeouts:
    recon_tool: 300      # 5 dakika
    scanner: 600         # 10 dakika
    nuclei_full: 1800    # 30 dakika
    sqlmap: 900          # 15 dakika
    nmap_full: 1200      # 20 dakika
    
  # Paralel çalıştırma limitleri
  concurrency:
    max_parallel_tools: 5
    max_requests_per_second: 10  # Global
    max_requests_per_host: 3    # Host başına
```

### Kali Linux Native Araç Katalogu

```yaml
# Tam araç listesi ve kategorileri
kali_native_tools:
  information_gathering:
    - nmap, masscan, rustscan
    - amass, subfinder, assetfinder, findomain
    - dnsrecon, dnsx, fierce
    - theHarvester, maltego
    - whatweb, wafw00f
    - enum4linux, smbclient
    
  vulnerability_analysis:
    - nikto, nuclei
    - wpscan, joomscan, droopescan
    - sqlmap, nosqlmap
    - searchsploit
    
  web_application:
    - burpsuite (API), zaproxy
    - dirb, gobuster, ffuf, feroxbuster
    - wfuzz
    - commix, xsstrike, dalfox
    - arjun, paramspider
    
  exploitation:
    - metasploit-framework
    - payload generators
    
  sniffing_spoofing:
    - wireshark/tshark
    - mitmproxy
    - netcat/ncat
    
  password_attacks:
    - hashcat, john
    - hydra, medusa
    - crunch (wordlist gen)
    
  wireless: # opsiyonel
    - aircrack-ng suite
    
# Kali dışı ek araçlar (Go/Rust tabanlı)
external_tools:
  go_tools:
    - httpx, katana, gospider, hakrawler
    - nuclei, subfinder, dnsx, naabu
    - dalfox, crlfuzz, interactsh
    - gau, waybackurls
    
  python_tools:
    - sqlmap, commix, ssrfmap, tplmap
    - xsstrike, corsy, smuggler
    - jwt_tool, openredirex
    
  rust_tools:
    - rustscan, feroxbuster
```

---

## 🤖 HİBRİT MOD (OTONOM / YARI-OTONOM) DETAYI

### Human Gateway — İnsan Onay Mekanizması

```yaml
autonomous_mode:
  description: "Tam otonom — insan müdahalesi olmadan çalışır"
  auto_approve:
    - passive_recon
    - active_recon (rate limited)
    - automated_scanning
    - fp_elimination
    - report_generation (draft)
  requires_human:
    - NOTHING — tamamen otonom
  auto_submit:
    - confidence >= 90 → otomatik gönder
    - confidence 70-89 → draft kaydet, bildirim gönder

semi_autonomous_mode:
  description: "Kritik noktalarda insan onayı ister"
  auto_approve:
    - passive_recon
    - dns_analysis
    - technology_detection
  requires_human:
    - "Aktif tarama başlatma"
    - "Exploit/PoC denemesi"
    - "Yüksek riskli araç çalıştırma"
    - "Rapor gönderimi"
    - "Scope belirsizliği kararları"
  notification_channels:
    - terminal_prompt  # CLI'da onay iste
    - slack_webhook    # Slack bildirimi
    - telegram_bot     # Telegram bildirimi

# Geçiş: CLI'dan mod değiştirme
# ./hunter --mode autonomous
# ./hunter --mode semi-autonomous
# ./hunter switch-mode autonomous  (çalışırken)
```

---

## 📊 RAPORLAMA STANDARTLARI

### HackerOne Rapor Şablonu

```markdown
## Summary
[1-2 cümle: Ne bulundu, nerede, etkisi ne]

## Severity
**CVSS Score:** X.X (Critical/High/Medium/Low)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

## Steps to Reproduce
1. Navigate to `https://target.com/endpoint`
2. Intercept the request with Burp Suite/mitmproxy
3. Modify parameter `X` with payload `Y`
4. Observe [zafiyet kanıtı]

## Impact
[İş etkisi: veri sızıntısı, hesap ele geçirme, vb.]

## Proof of Concept
```http
[HTTP Request]
```
```http
[HTTP Response]
```

## Suggested Fix
[Actionable düzeltme önerisi]

## References
- CWE-XXX: [açıklama]
- OWASP: [kategori]
```

---

## ⚙️ KONFİGÜRASYON VE ORTAM

### Gerekli Ortam Değişkenleri

```bash
# Brain API (Remote LM Studio)
WHAI_PRIMARY_API_URL=http://127.0.0.1:1239
WHAI_SECONDARY_API_URL=http://127.0.0.1:1239
WHAI_PRIMARY_API_KEY=sk-lm-xxxxx    # LM Studio API token (required if server auth enabled)
WHAI_SECONDARY_API_KEY=sk-lm-xxxxx  # Same token (same server)

# Model Paths (local backend only)
WHAI_PRIMARY_MODEL_PATH=/path/to/baronllm-v2-offensivesecurity-q8_0.gguf
WHAI_SECONDARY_MODEL_PATH=/path/to/baronllm-v2-offensivesecurity-q8_0.gguf  # Same model, /no_think mode
WHAI_FALLBACK_MODEL_PATH=/path/to/deephat-v1-7b-q4_k_m.gguf  # Emergency fallback

# API Keys (bug bounty & OSINT)
HACKERONE_API_TOKEN=
BUGCROWD_API_TOKEN=
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
GITHUB_TOKEN=

# Notification
SLACK_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Database
DATABASE_URL=sqlite:///output/whai.db

# Runtime
WHAI_MODE=semi-autonomous  # autonomous | semi-autonomous
WHAI_SCAN_PROFILE=balanced  # stealth | balanced | aggressive
WHAI_LOG_LEVEL=INFO
WHAI_MAX_PARALLEL_TOOLS=5
WHAI_GPU_LAYERS=-1  # -1 = auto
```

### Minimum Sistem Gereksinimleri

```yaml
minimum:
  cpu: "8 cores (16 threads önerilen)"
  ram: "16GB (32GB+ önerilen — BaronLLM v2 15B model için)"
  gpu: "NVIDIA GPU 16GB+ VRAM (opsiyonel ama önerilen)"
  storage: "100GB+ SSD"
  os: "Kali Linux 2024+ / Ubuntu 22.04+ / Debian 12+"
  python: "3.11+"
  
recommended:
  cpu: "16 cores / 32 threads"
  ram: "64GB+"
  gpu: "NVIDIA RTX 4090 / A100 (24GB+ VRAM)"
  storage: "500GB NVMe SSD"
  os: "Kali Linux 2025+"
  python: "3.12+"
```

---

## 🔐 GÜVENLİK VE ETİK KURALLAR

```yaml
ethical_rules:
  # ZORUNLU
  mandatory:
    - "SADECE açıkça izin verilmiş (scope içi) hedefleri test et"
    - "Bug bounty programı kurallarına TAMAMEN uy"
    - "Hiçbir veriyi silme, değiştirme veya çalma"
    - "Minimum düzeyde exploit — sadece PoC için yeterli"
    - "Rate limit'lere uy, hedef sisteme zarar verme"
    - "Kişisel verilere erişildiyse HEMEN raporla ve sil"
    - "İkinci hedeflere (pivoting) izinsiz geçme"
    
  # Scope Doğrulama
  scope_enforcement:
    - "Her araç çalıştırılmadan önce hedef scope kontrolü"
    - "Wildcard scope'larda bile alt domain doğrulaması"
    - "IP resolution sonrası scope yeniden kontrolü"
    - "Redirect takibinde scope dışına çıkma kontrolü"
    
  # Legal
  legal:
    - "Sadece legal bug bounty programlarında kullan"
    - "Yetkilendirme belgesi olmadan ASLA kullanma"
    - "Tüm aktiviteleri logla (yasal koruma için)"
```

---

## 🧪 TEST STRATEJİSİ

```yaml
testing:
  unit_tests:
    - "Her araç wrapper'ı için parse testi"
    - "Brain router görev eşleme testi"
    - "FP detection kalıp eşleme testi"
    - "Scope validator testi"
    - "Confidence scorer testi"
    
  integration_tests:
    - "Araç zinciri end-to-end testi"
    - "Brain engine soru-cevap testi"
    - "Pipeline akış testi"
    
  mock_testing:
    - "Vulnerable-by-design lab'lar ile test:"
    - "  - DVWA, bWAPP, Juice Shop"
    - "  - HackTheBox, TryHackMe lab'ları"
    - "  - Custom vulnerable apps"
    
  fp_testing:
    - "Bilinen FP senaryoları ile FP engine testi"
    - "Bilinen gerçek zafiyet senaryoları ile FN testi"
```

---

## � LOGLAMA SİSTEMİ (Detaylı)

Bot, geliştirme ve hata ayıklama sürecini kolaylaştırmak için **multi-sink loguru** tabanlı kapsamlı bir loglama sistemi kullanır. Tüm log altyapısı `src/utils/logger.py` içinde tanımlıdır.

### Log Sink'leri (6 Katmanlı)

| Sink | Dosya | Seviye | Açıklama |
|------|-------|--------|----------|
| **KONSOL** | stdout | Konfigüre edilebilir (varsayılan INFO) | Renkli, okunabilir, geliştirici dostu |
| **ANA LOG** | `output/logs/whai.log` | TRACE+ (tümü) | JSON serialize, rotasyonlu (50MB), 30 gün retention |
| **HATA LOG** | `output/logs/whai_errors.log` | WARNING+ | Sadece uyarı ve hatalar, hızlı tarama için |
| **DEBUG LOG** | `output/logs/whai_debug.log` | TRACE+DEBUG | Sadece `dev_mode: true` iken aktif |
| **BRAIN LOG** | `output/logs/brain.log` | DEBUG+ | Brain engine istek/yanıt loglama (`src.brain.*` filtresi) |
| **TOOL LOG** | `output/logs/tools.log` | DEBUG+ | Araç çalıştırma detayları (`src.tools.*` + `src.workflow.*` filtresi) |

Tüm dosya sink'leri `enqueue=True` (thread-safe async yazma) ve `backtrace=True, diagnose=True` (detaylı traceback) ile çalışır.

### Yapılandırılmış Olay Loggerları

Kod içinde doğrudan `logger.info(...)` yerine **olay bazlı structured logger** fonksiyonları kullanılmalıdır:

```python
from src.utils.logger import (
    log_tool_execution,    # Araç çalıştırma sonucu
    log_brain_call,        # Brain LLM istek/yanıt
    log_finding,           # Zafiyet bulgusu
    log_stage_transition,  # Workflow aşama geçişi
    log_scope_check,       # Scope doğrulama sonucu
    log_http_exchange,     # HTTP istek/yanıt çifti
    log_startup_diagnostics,  # Başlangıç sistem bilgisi
)
```

Bu fonksiyonlar her log kaydına otomatik olarak yapılandırılmış `extra` alanları ekler (ör: `tool_name`, `duration_ms`, `exit_code`, `model`, `confidence`, `severity` vb.) ve JSON serialize edildiğinde aranabilir/filtrelenebilir veri üretir.

### Bağlam Yönetimi (Thread-Local Context)

```python
from src.utils.logger import set_log_context, clear_log_context, log_context

# Manuel bağlam ekleme
set_log_context(target="example.com", pipeline="full_scan")
logger.info("Tarama başlıyor")  # extra'ya target + pipeline eklenir
clear_log_context()

# Context manager ile otomatik temizlik
with log_context(target="example.com", stage="recon"):
    logger.info("Recon başlıyor")   # extra: target + stage
# Otomatik temizlendi
```

### Performans Ölçümü

```python
from src.utils.logger import log_duration

async with log_duration("nmap_scan", warn_threshold=60.0):
    await nmap.run(target, options)
# Otomatik log: "nmap_scan completed in 12.34s"
# warn_threshold aşılırsa WARNING seviyesinde loglanır
```

### Exception Handling

- `sys.excepthook` override → Yakalanmamış exception'lar otomatik olarak CRITICAL seviyesinde loglanır
- `format_exception_chain(exc)` → `__cause__` / `__context__` dahil tam exception zincirini string olarak döner
- Tüm dosya sink'lerinde `backtrace=True, diagnose=True` → loguru'nun detaylı değişken-düzeyi traceback'i

### Hassas Veri Koruma

Önceden derlenmiş regex (`_SENSITIVE_RE`) ile aşağıdaki kalıplar otomatik maskelenir:
`api_key`, `api_token`, `secret`, `password`, `credential`, `token`, `bearer`, `cookie`, `jwt`, `private_key`, `access_key`, `secret_key`, `client_secret`, `refresh_token`

Örnek: `api_key=sk-abc123` → `api_key=***REDACTED***`

### Session ID

Her bot çalıştırması benzersiz bir `session_id` üretir. Bu ID tüm log kayıtlarına `_inject_context()` patcher'ı ile otomatik eklenir. Log dosyalarında `session_id` ile filtreleyerek belirli bir çalıştırmanın tüm loglarını izole edebilirsiniz.

### Geliştirici Tanılama (`diagnose` CLI Komutu)

`src/utils/dev_diagnostics.py` modülü proje sağlık kontrolü yapar:

```bash
# CLI'dan tanılama çalıştırma
python -m src.cli diagnose
python -m src.cli diagnose --skip-tools    # Sistem araç kontrolünü atla
python -m src.cli diagnose --skip-brain    # Brain bağlantı kontrolünü atla
```

Kontrol kategorileri:
- **import**: 16 kritik modülün import edilebilirliği + attribute erişimi
- **pip**: 10 temel Python paketinin kurulu olup olmadığı
- **config**: `settings.yaml`, `models.yaml`, `tools.yaml`, `platforms.yaml`, `.env` dosyaları
- **system**: RAM, disk, GPU, Python versiyonu
- **tools**: 8 temel güvenlik aracının PATH'te bulunup bulunmadığı (nmap, nuclei, ffuf, httpx, subfinder, sqlmap, nikto, katana)
- **brain**: Primary & secondary model API endpoint'lerine `/v1/models` health check

Her kontrol `ok` / `warn` / `fail` / `skip` durumu ile raporlanır.

### settings.yaml Loglama Konfigürasyonu

```yaml
logging:
  level: DEBUG           # Konsol seviyesi: TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
  log_dir: output/logs   # Log dosyaları dizini (otomatik oluşturulur)
  rotation: "50 MB"      # Log dosya rotasyon büyüklüğü
  retention: "30 days"   # Eski logları saklama süresi
  serialize: true        # JSON formatında dosya logları
  dev_mode: true         # true → DEBUG log sink aktif, detaylı traceback
  # Otomatik oluşturulan dosyalar:
  #   {log_dir}/whai.log          — Tüm seviyeler (ana log)
  #   {log_dir}/whai_errors.log   — WARNING+ (hata log)
  #   {log_dir}/whai_debug.log    — TRACE+DEBUG (dev_mode=true iken)
  #   {log_dir}/brain.log         — Brain engine logları
  #   {log_dir}/tools.log         — Araç çalıştırma logları
```

### Loglama Best Practices (Copilot İçin)

1. **Structured logger kullan**: `log_tool_execution()` / `log_brain_call()` gibi olay fonksiyonlarını tercih et, ham `logger.info()` yerine
2. **Context ekle**: Uzun işlemlerde `log_context(target=..., stage=...)` ile bağlam sağla
3. **Süre ölç**: I/O ve araç çalıştırmalarında `log_duration()` ile performans takibi yap
4. **Exception chain**: `except` bloklarında `logger.exception()` veya `format_exception_chain()` kullan
5. **Hassas veri**: API key, token, credential'ları asla doğrudan log mesajına yazma — `_sanitize_message()` otomatik çalışır ama yine de dikkatli ol
6. **Seviye seçimi**: TRACE (en detaylı) → DEBUG → INFO → WARNING → ERROR → CRITICAL
7. **Test/CI ortamı**: `dev_mode: false` ve `level: WARNING` ile gereksiz log çıktısı azaltılır

---

## �📋 GELİŞTİRME KURALLARI (Copilot için)

### Kod Yazma Kuralları

1. **Python 3.11+ özelliklerini kullan**: type hints, match-case, async/await
2. **Her modül**: docstring, type annotation, error handling zorunlu
3. **Async-first**: Tüm I/O operasyonları async olmalı
4. **Pydantic**: Tüm veri modelleri Pydantic BaseModel kullanmalı
5. **Structured logging**: `src/utils/logger.py` multi-sink sistemi ile yapılandırılmış log — `log_tool_execution()`, `log_brain_call()`, `log_finding()` gibi olay fonksiyonlarını kullan
6. **Error handling**: Her araç çalıştırması try/except ile sarmalanmalı
7. **Rate limiting**: Her dış istek rate limiter'dan geçmeli
8. **Scope check**: Her hedef operasyonunda scope doğrulama zorunlu
9. **Testing**: Her yeni fonksiyon için en az birim testi
10. **Security**: Hassas veri (API key, credential) asla loglanmamalı — `_SENSITIVE_RE` otomatik maskeler ama yine de dikkatli ol
11. **Diagnostics**: Yeni modül eklerken `dev_diagnostics.py` → `_CRITICAL_MODULES` listesine ekle
12. **Log context**: Araç/pipeline fonksiyonlarında `log_context()` ile target/stage bilgisi sağla
13. **Dokümantasyon güncellemesi**: Her önemli değişiklik sonrasında `.github/copilot-instructions.md` dosyasını güncellemek ZORUNLUDUR — yeni modüller, yeni yetenekler, değişen sayılar, yeni dosyalar mutlaka yansıtılmalıdır

### Import Sırası
```python
# 1. Standard library
import asyncio
import json
from pathlib import Path

# 2. Third-party
from pydantic import BaseModel
from loguru import logger
from llama_cpp import Llama

# 3. Local
from src.brain.engine import BrainEngine
from src.tools.base import SecurityTool
```

### Commit Mesajı Formatı
```
feat(brain): add dual-model routing logic
fix(fp-engine): correct WAF detection false positive
refactor(tools): unified tool output parser
docs(workflow): update pipeline documentation
test(scanner): add nuclei wrapper unit tests
```

### Dosya Adlandırma
- Snake_case: `vulnerability_analyzer.py`
- Wrapper'lar: `{tool_name}_wrapper.py`
- Test dosyaları: `test_{module_name}.py`

---

## 🚀 BAŞLANGIÇ SIRASI (Implementation Priority)

```
Phase 1 — Foundation (Temel):
  ├── src/brain/engine.py          # Model yükleme ve inference
  ├── src/brain/router.py          # Görev-model eşleme
  ├── src/tools/base.py            # Araç temel sınıfı
  ├── src/tools/registry.py        # Araç kayıt sistemi
  ├── src/tools/executor.py        # Araç çalıştırma motoru
  ├── src/utils/logger.py          # Loglama
  ├── src/utils/scope_validator.py # Scope doğrulama
  ├── config/settings.yaml         # Ana konfigürasyon
  └── src/main.py                  # Giriş noktası

Phase 2 — Recon (Keşif):
  ├── src/tools/recon/subdomain/   # Subdomain araçları
  ├── src/tools/recon/port_scan/   # Port tarama
  ├── src/tools/recon/web_discovery/# Web keşfi
  ├── src/tools/recon/dns/         # DNS
  └── src/tools/recon/osint/       # OSINT

Phase 3 — Scanning (Tarama):
  ├── src/tools/scanners/          # Tüm tarayıcılar
  ├── src/tools/fuzzing/           # Fuzzing araçları
  └── src/tools/api_tools/         # API güvenlik

Phase 4 — FP Engine (Doğrulama):
  ├── src/fp_engine/               # False positive motoru
  └── src/analysis/                # Analiz modülleri

Phase 5 — Workflow (İş Akışı):
  ├── src/workflow/orchestrator.py  # Orkestratör
  ├── src/workflow/state_machine.py # Durum makinesi
  └── src/workflow/pipelines/       # Pipeline'lar

Phase 6 — Reporting (Raporlama):
  ├── src/reporting/               # Rapor sistemi
  └── src/cli.py                   # CLI arayüzü

Phase 7 — Integration (Entegrasyon):
  ├── Platform API'leri
  ├── Bildirim sistemi
  └── Docker containerization
```

---

## 🌐 İNTERNET ERİŞİMİ VE GERÇEK DÜNYA ETKİLEŞİMİ

Bot gerçek dünyada çalışan bir güvenlik sistemidir. LLM'ler internete erişerek:
- Hedeflere HTTP istekleri gönderir (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD/TRACE)
- Response'ları derin analiz eder (status code, header, body, timing)
- Yeni CVE'leri araştırır (NVD, MITRE, Exploit-DB)
- Yeni teknikler öğrenir (PortSwigger Research, Project Zero)
- Disclosed raporları analiz eder (HackerOne Hacktivity)
- WAF bypass teknikleri günceller
- OOB (Out-of-Band) callback ile blind zafiyet doğrular (Interactsh)

### LLM İnternet Kullanım Senaryoları

```yaml
senaryo_keşif: "LLM → HTTP GET hedef → Response analiz → Fingerprint → CVE araştır → Exploit test"
senaryo_test: "LLM → Hipotez üret → Payload tasarla → HTTP POST hedef → Response analiz → Doğrula"
senaryo_exploit: "LLM → Blind SQLi tespiti → Custom script yaz → Veri çıkar → PoC + Rapor"
senaryo_öğrenme: "LLM → Mevcut teknikler yetersiz → Web search → Yeni teknik öğren → Template yaz → Test et"
senaryo_oob: "LLM → Interactsh URL oluştur → Payload ile hedefe gönder → Callback kontrol → SSRF doğrulandı"
```

### Response Deep Analysis

LLM her response'u detaylı analiz eder:
- **Status code**: 200, 301/302 (redirect leak?), 403 (WAF mı ACL mi?), 500 (stack trace?)
- **Headers**: Server versiyonu, X-Powered-By, Set-Cookie (HttpOnly? Secure? SameSite?), CSP, CORS, HSTS
- **Body**: Error messages, HTML comments, hidden fields, JS endpoint/secret leak, stack trace
- **Timing**: Baseline vs payload response time farkı → Blind detection

---

## 🧊 BUZDAĞI META-DİREKTİFİ (Anti-Completion)

Bu dokümantasyon ve kodda görülen her şey, yapılması gerekenin çok küçük bir kısmıdır:

```yaml
buzdağı_ilkesi:
  xss_payloads: "Mevcut 759 → Gerçek ihtiyaç 50.000+ (her tag, event, encoding, WAF, browser)"
  nuclei_templates: "Mevcut 59 → Gerçek ihtiyaç 10.000+ (her zafiyet × her teknoloji)"
  exploit_scripts: "Mevcut ~10 → Gerçek ihtiyaç 5.000+ (her vuln × her context × her WAF)"
  keşif_teknikleri: "Mevcut ~20 → Gerçek ihtiyaç 200+ (subdomain, JS, API, cloud, parametre)"
  toplam_payload: "Mevcut 3,669 → Gerçek ihtiyaç 25.000+ (14 kategori × çoklu encoding × WAF bypass)"
  özel_denetleyiciler: "Mevcut 25 → Gerçek ihtiyaç 100+ (her OWASP × her teknoloji × her context)"
  
anti_completion_kuralları:
  - "'Bu dosyadaki örnekleri yaptım' = 'HENÜZ BAŞLADIM'"
  - "Her template'in 100+ varyasyonu yazılmalı"
  - "Her zafiyet türü × her teknoloji × her context = yeni test"
  - "Daha önce bulamamamız, orada zafiyet olmadığı anlamına gelmez"
  - "'Yeterli' diye bir kavram YOKTUR"
```

### Genişletilmesi Gereken Saldırı Alanları

Bu dokümanda detaylandırılmamış AMA implementasyonda ele alınması gereken alanlar:

| Alan | Kapsam | Durum |
|------|--------|-------|
| HTTP Request Smuggling | CL.TE, TE.CL, TE.TE, H2C, request splitting | ✅ Uygulandı (http_smuggling_prober.py) |
| Web Cache Poisoning | Unkeyed headers, cache deception, CDN-specific | ✅ Uygulandı (cache_poisoning_checker.py) |
| WebSocket Security | CSWSH, message injection, auth bypass | ✅ Uygulandı (websocket_checker.py) |
| GraphQL Deep | Introspection, alias brute force, batch query, mutation abuse | ✅ Uygulandı (graphql_deep_scanner.py) |
| API Security (OWASP Top 10) | BFLA, BOLA, mass assignment, excessive data exposure | ✅ Uygulandı (bfla_bola_checker.py + mass_assignment_checker.py) |
| Deserialization | Java/PHP/Python/.NET insecure deserialization | ✅ Uygulandı (deserialization_checker.py) |
| Prototype Pollution | JavaScript prototype chain manipulation | ✅ Uygulandı (prototype_pollution_checker.py) |
| JWT Deep Security | alg:none, weak secret, kid injection, claim tampering | ✅ Uygulandı (jwt_checker.py) |
| WAF Adaptive Strategy | Fingerprint + per-WAF encoding/rate/header strategies | ✅ Uygulandı (waf_strategy.py) |
| LLM Cross-Finding | Rule + LLM hybrid attack chain discovery | ✅ Uygulandı (correlation_engine.detect_chains_llm) |
| Cloud Native | K8s, serverless, IAM misconfig, S3/Blob exposure | ⬜ Planlandı (Tier 2) |
| CI/CD Security | Pipeline injection, dependency confusion, secret leak | ✅ Uygulandı (cicd_checker.py) |
| Novel Research | HTTP/2-3 testing, WebTransport, WASM security, AI endpoint abuse | 🔄 HTTP/2-3 uygulandı (http2_http3_checker.py), geri kalanı araştırma gerekli |

### Sonsuz İyileştirme Döngüsü

```
while true:
  1. İstihbarat topla (yeni CVE, yeni teknik, hedef değişiklikleri)
  2. Keşfi derinleştir (yeni subdomain, yeni endpoint, yeni parametre)
  3. Test & exploit (yeni hipotez, yeni payload, yeni yaklaşım)
  4. Template/exploit geliştir (daha fazla varyasyon, daha fazla kapsam)
  5. Öğrenilenleri uygula (başarılı teknik → genelleştir, başarısız → analiz et)
  6. Park edilen hedeflere geri dön (yeni tekniklerle eski hedefleri yeniden test et)
  7. Anti-completion kontrolü ("Bitti mi?" → HAYIR, asla bitmez)
  8. Sonraki seviye planla (lateral thinking, yeni perspektif, daha yaratıcı)
```

---

## 📌 ÖNEMLİ NOTLAR

1. **Model dosyaları repo'ya dahil DEĞİLDİR** — `scripts/download_models.sh` ile indirilir
2. **Wordlist'ler**: SecLists + özel listeler — `scripts/setup_wordlists.sh` ile indirilir
3. **Kali araçları**: `scripts/setup_kali_tools.sh` ile eksik araçlar kurulur
4. **Go araçları**: `scripts/setup_go_tools.sh` ile Go tabanlı araçlar kurulur
5. **GPU opsiyoneldir** ama model inference için şiddetle önerilir
6. **İlk çalıştırmada** `scripts/health_check.sh` ile sistem kontrolü yapılmalı
7. **Her tarama oturumu** benzersiz bir session ID ile loglanır
8. **Rate limiting** her zaman aktiftir — devre dışı bırakılamaz
9. **Scope validation** her zaman aktiftir — devre dışı bırakılamaz
10. **Log dosyaları** `output/logs/` altında otomatik oluşturulur — `.gitignore`'da hariç tutulur
11. **`whai diagnose`** komutu ile geliştirme ortamı sağlık kontrolü yapılabilir
12. **Brain backend** `local` veya `remote` olabilir — `config/settings.yaml` → `brain.*.backend` ile değiştirilir
13. **Rapor auto-submit KAPALI** — 4 katmanlı güvenlik kilidi ile korunur, ASLA otomatik gönderilmez

---

*Bu doküman, WhiteHatHacker AI projesinin tek kaynak belgesidir (Single Source of Truth). Tüm geliştirme bu mimari ve kurallara uygun yapılmalıdır.*
