# Seku — مرجع المميزات وطرق الفحص

> مرجع شامل وسريع لكل ما يقدّمه نظام Seku (sec.erticaz.com). مُحدّث: 2026-08-16.
> النطاق: **sec.erticaz.com فقط** (تطبيق Coolify `vscan-mohesr`). نظام `webmetrics.mohesr.gov.iq` منفصل ولا علاقة له.

---

## 1) طرق الفحص (الماسحات) — ~46 فاحصاً

### أ. فحوص التهيئة والنقل (سلبية — تعمل دائماً)
| الفئة | ماذا تفحص |
|---|---|
| `ssl` | HTTPS، صلاحية/انتهاء/توقيع ذاتي للشهادة، إصدار TLS وقوة الـcipher، تحويل HTTP→HTTPS |
| `headers` | **تحليل CSP حقيقي** (unsafe-inline/eval مع وعي nonce/hash/strict-dynamic)، X-Frame-Options/frame-ancestors، HSTS، X-Content-Type-Options، Referrer-Policy، Permissions-Policy |
| `advanced_security` | COEP / COOP / CORP، OCSP stapling |
| `cookies` | Secure / HttpOnly / SameSite لكل كوكي |
| `mixed_content` | محتوى مختلط (HTTP داخل HTTPS) |
| `dns` | SPF، DMARC، CAA |
| `email_security` | DKIM (عدّة selectors)، BIMI، تجميع SPF+DKIM+DMARC |
| `waf` | كشف جدار حماية التطبيقات |
| `ddos` | كشف CDN، رؤوس rate-limit، سبر WAF، مرونة Slowloris |
| `ports` | كشف المنافذ المفتوحة الشائعة |
| `zone_transfer` | نقل نطاق DNS (AXFR) |
| `server_info` | كشف السيرفر/الإصدار |
| `tech_stack` | بصمة التقنيات المستخدمة |
| `info_disclosure` | تسريب معلومات حسّاسة |
| `directory` | سرد المجلدات |
| `hosting` / `performance` / `content` / `seo` | جودة الاستضافة/الأداء/المحتوى/السيو (درجة منفصلة) |
| `malware` / `threat_intel` | كشف برمجيات خبيثة + سمعة تهديدات |

### ب. فحوص فعّالة (اكتشاف ثغرات — بعضها opt-in ضمن الفحص العميق)
| الفئة | ماذا تفحص |
|---|---|
| `xss` | XSS منعكس + أنماط DOM، مع **تأكيد breakout** (تقليل الإيجابيات الكاذبة) |
| `sqli` | SQLi خطأي (مقارنة baseline) + **أعمى** (زمني + منطقي) |
| `ssrf` | SSRF على البارامترات + توقيعات metadata سحابية |
| `open_redirect` | إعادة توجيه مفتوحة (تحقّق من مضيف الوجهة) |
| `cors` | wildcard + credentials + انعكاس origin |
| `http_methods` | الطرق المسموحة (PUT/DELETE/TRACE...) |
| `secrets` / `js_secrets` | أسرار في HTML و JS الخارجي |
| `js_libraries` | مكتبات JS بإصدارات مصابة (jQuery وغيرها) |
| `backup_files` | `.git/HEAD`، `.svn`، `.env.*`، نسخ SQL/أرشيف |
| `cms_cve` | ثغرات CVE لأنظمة إدارة المحتوى |
| `wordpress` / `wp_deep` | فحص ووردبريس + فحص معمّق |
| `subdomains` | تعداد النطاقات الفرعية (crt.sh + HackerTarget + OTX + RapidDNS + WebArchive + **subfinder**) + **كشف takeover** |
| `graphql` | كشف endpoint + **introspection مفتوح** |
| `jwt_security` | `alg:none`، مفتاح HMAC ضعيف (كسر بقائمة)، exp مفقود |
| `access_control` | **IDOR / BOLA تفاضلي** (جلستان: يقارن وصول مستخدم لبيانات آخر) |
| `login` | اكتشاف نقطة الدخول + قفل المحاولات + تعداد المستخدمين + بيانات افتراضية (خلف تفويض) |
| `passive_urls` | **اكتشاف URLs سلبي** عبر gau (Wayback/CommonCrawl/OTX/URLScan): روابط تاريخية، روابط ببارامترات (مرشّحات حقن)، نقاط حسّاسة تاريخية |

### ج. تكاملات أدوات خارجية (opt-in، تشغيل binary)
| الأداة | الدور | التفعيل |
|---|---|---|
| **nuclei** v3 (+ القوالب الكاملة) | آلاف قوالب CVE/تعرّض/تهيئة/دخول-افتراضي | `enable_nuclei` أو `SEKU_ENABLE_NUCLEI=1` |
| **katana** | زحف واكتشاف سطح الهجوم | `enable_crawl` أو `SEKU_ENABLE_KATANA=1` |
| **dalfox** | XSS متقدّم مؤكَّد | `enable_dalfox` |
| **ffuf** | اكتشاف محتوى/مسارات بقائمة كلمات | `enable_ffuf` |
| **interactsh** | تأكيد Blind SSRF (OOB) | `enable_oob` |
| **gau / waybackurls** | روابط تاريخية سلبية | مع الزحف أو `SEKU_ENABLE_GAU=1` |
| **subfinder** | نطاقات فرعية من 30+ مصدر | تلقائي ضمن فاحص subdomains |

### د. أدوات مستقلة (خارج الفحص الرئيسي)
- **تسريب البيانات** (HIBP) · **اكتشاف النطاقات** (Certificate Transparency) · **بحث CVE** · **الروابط المشتركة/شجرة التحقيق** (IP/nameserver/بريد مشترك بين المواقع).

---

## 2) سياسات الفحص
| السياسة | التغطية | الزمن التقريبي | الدفع |
|---|---|---|---|
| **خفيف (light)** | 8 فئات أساسية | ~30ث | مجاني |
| **قياسي (standard)** | 16 فئة | ~60ث | مجاني |
| **عميق (deep)** | 40+ فئة (يشمل الفعّالة + الأدوات + IDOR/GraphQL/JWT/passive_urls) | ~3–5د | **مدفوع لكل نطاق** |

## 3) الفحص المُصادَق (Authenticated)
- حقن **جلسة** (كوكي/رأس Bearer) في katana و nuclei → فحص خلف تسجيل الدخول.
- **IDOR/BOLA**: إضافة **جلسة مستخدم ثانٍ** لمقارنة الوصول.
- حقول: `auth_cookie`، `auth_header`، `auth_cookie_b` (صفحة الفحص → «فحص مُصادَق»).

## 4) نظام التقييم (Scoring)
- **نموذج خصم**: يبدأ 1000 ويخصم لكل ثغرة حسب خطورتها (critical/high/medium/low) × (fail/warn) × الثقة، بسقف لكل فئة.
- **cap حرِج**: ثغرة حرِجة مؤكّدة (حقن/تسريب/malware) تخفض التقدير إلى F.
- إثراء تلقائي: **CVSS v3.1**، الثقة (Confidence)، تعيين **OWASP/CWE**.
- تقدير **A+ … F**، ودرجة **جودة** منفصلة (أداء/سيو لا تؤثر على الأمان).
- قيم الخصم قابلة للضبط: `SEKU_PEN_CRIT/HIGH/MED/LOW/WARN_PCT/CATCAP`.
- أدمن: `POST /api/recompute-scores` يعيد حساب كل النتائج المخزّنة بالصيغة الحالية.

---

## 5) منصّة الـ SaaS
- **تسجيل ذاتي** + منظمات + أدوار.
- **تحقّق ملكية النطاق**: سجل **DNS TXT** أو **ملف** `/.well-known/seku-verify.txt`.
- **الدفع لكل فحص عميق** (حوالة داخلية يدوية): طلب → إدخال رقم الحوالة → **رفع إثبات** → موافقة الأدمن → رصيد → فحص. الأدمن يتجاوز التحقق والدفع.
- **بريد معاملات** على أحداث الطلب/الدفع + تنبيه الأدمن.
- **صفحة أسعار عامة** + السعر من الإعدادات.
- **تقرير عام قابل للمشاركة** `/r/:token` + **شارة «Scanned by Seku»** (SVG قابلة للتضمين).
- **تحميل الوكلاء المحليين** (Windows/Mac/Linux) لفحص الشبكات الداخلية + عدّاد تحميلات.
- **مفاتيح API** + **Webhooks** (Slack/Telegram/Discord/**MS Teams**/مخصّص) + **فحوص مجدولة**.
- **تحليل AI** للنتائج + **مساعد محادثة AI**.
- **Triage** للنتائج، **مقارنة/دِف** بين فحصين، **لوحة ترتيب**، **لوحة تحكم**، **شجرة تحقيق/روابط مشتركة**.
- **onboarding** أول-تشغيل + **إعادة فحص بنقرة** + **فحص فوري تشويقي على الصفحة الرئيسية**.
- إدارة (أدمن): مستخدمون، إعدادات، SEO، طلبات الدفع، الأوامر الإدارية، proxy pool، إعداد البريد.

## 6) التقارير والمخرجات
- **PDF** (بالعربية/الإنجليزية) · **SARIF** · **CSV** · **تقرير امتثال OWASP** · **أولوية الإصلاح** · **أدلة معالجة** حسب نوع السيرفر · إنشاء **GitHub/Jira issue**.

## 7) الموثوقية وأمان المنصّة نفسها
- **JWT** إلزامي قوي (رفض الإقلاع بالافتراضي) · **تحديد معدّل** (دخول/تسجيل/AI) · **حارس SSRF مركزي** (`safehttp`) · **عزل تنظيمي** على كل نقاط `:id` (لا IDOR بين المنظمات) · **SQLite WAL** · **إطفاء رشيق** · **سقف تزامن** يمنع OOM · استئناف الفحوص بنفس الإعدادات.

## 8) واجهة الاستخدام
- **لوحة تحكم** بتنقّل مجمّع (الرئيسية/التحليل/الأتمتة/الإدارة/الحساب) + **هيدر علوي موحّد**.
- **هيدر عام موحّد** لكل الصفحات العامة (Landing/Pricing/Methodology/Docs/Downloads).
- ثنائية اللغة (عربي/إنجليزي) + نظام تنبيهات (toast) + جلسة منزلقة (لا تسجيل خروج مفاجئ).

---

## 9) أهم متغيّرات البيئة
| المتغيّر | الغرض |
|---|---|
| `JWT_SECRET` | **إلزامي** (≥32 حرف) — بدونه لا يقلع النظام |
| `SEKU_ENABLE_NUCLEI/KATANA/GAU` | تفعيل أدوات على مستوى الخادم |
| `SEKU_MAX_CONCURRENT_SCANS` | سقف الفحوص المتزامنة (افتراضي 3) |
| `SEKU_SCANNER_TIMEOUT` | مهلة كل فاحص (افتراضي 240ث) |
| `SEKU_PEN_*` | معايرة خصومات التقييم |
| `deep_scan_price_iqd` + `payment_*` | (إعدادات) سعر وطريقة وحساب الدفع |

> **قيد التطوير (خارطة الدراسة):** خط ProjectDiscovery (httpx/naabu)، nuclei -dast (SSTI/LFI/XXE/CMDi)، arjun، testssl، وضع «الوكيل الأمني AI»، وتقارير بمستوى مختبِري الاختراق (CVSS vectors + retest delta + نتائج مؤكّدة).
