# أدوات GitHub المرشّحة للدمج — بحث حيّ (نجوم فعلية)

> مرتّبة حسب: **يسدّ فجوة حقيقية × سهولة الدمج**. نمط الدمج الأسهل والمُثبَت في نظامنا:
> أداة **Go** تُثبَّت بـ`go install` في مرحلة `nuclei-builder` بالـDockerfile ثم `COPY --from`
> وتُستدعى كـbinary — تماماً مثل nuclei/katana/subfinder/gau الموجودة.

## المستوى 1 — Go «drop-in» (نفس نمطنا، أقلّ جهد، أعلى عائد)
| الأداة | ⭐ | يسدّ | ملاحظة |
|---|---|---|---|
| **projectdiscovery/naabu** | 6.2k | **فحص المنافذ للشبكة الداخلية** (فجوة العميل) | 🥇 يحوّل عميل الديسكتوب لفاحص شبكة فعلي |
| **projectdiscovery/httpx** | 10.3k | سبر HTTP + كشف تقنيات + CDN + حالة/عنوان | 🥇 يغذّي الأنبوب ويحسّن تغطية الويب |
| **trufflesecurity/trufflehog** | 27.5k | **أسرار مسرّبة مع تحقّق حيّ** (المفتاح فعّال؟) | 🥇 ترقية ضخمة على فاحص secrets الاستدلالي |
| **projectdiscovery/tlsx** | 1.1k | جرد TLS/شهادات عميق (إصدار/شيفرة/SAN/انتهاء) | يسدّ فجوة testssl + يقوّي OSINT |
| **projectdiscovery/dnsx** | 2.8k | DNS متعدّد (A/PTR/CNAME/wildcard) + حلّ الفروع | يقوّي OSINT واكتشاف النطاقات الفرعية |
| **projectdiscovery/asnmap** | 1.1k | ASN → نطاقات الشبكة (CIDR) | OSINT بنية تحتية + توسيع أهداف الشبكة |
| **projectdiscovery/uncover** | 3.0k | Shodan/Censys/Fofa (تعرّض الإنترنت) | OSINT «ما هو مكشوف علناً» (مفاتيح اختيارية) |
| **projectdiscovery/mapcidr** | 1.2k | عمليات CIDR (توسيع/تقسيم) | أداة مساعدة للفحص الجماعي/الشبكي |
| **sa7mon/S3Scanner** | 3.2k | مخازن سحابية مكشوفة (S3/GCS…) | نتيجة شائعة، Go بسيط |
| **projectdiscovery/wappalyzergo** | 1.1k | كشف تقنيات (مكتبة Go) | تُستورَد كاعتماد لتقوية tech_stack |

## المستوى 2 — عالية القيمة (Go/غير Go، جهد متوسط)
| الأداة | ⭐ | يسدّ | ملاحظة |
|---|---|---|---|
| **s0md3v/Arjun** | 6.4k | **اكتشاف بارامترات HTTP** → يغذّي فاحصات الحقن | 🥇 يعالج فجوة P0 (الاختبار على الرئيسية فقط). Python |
| **sensepost/gowitness** | 4.5k | **لقطات شاشة كدليل/PoC** بالتقارير | Go لكن يحتاج Chrome في الصورة (أثقل) |
| **assetnote/kiterunner** | 3.2k | **اكتشاف مسارات API** (Swagger/routes) | يسدّ فجوة اختبار API. Go |
| **jaeles-project/jaeles** | 2.4k | اختبار ويب بالتواقيع | يتقاطع مع nuclei (اختياري) |
| **projectdiscovery/shuffledns** + **alterx** | 1.7k/1k | تخمين نطاقات فرعية نشط | يحتاج massdns (أثقل) |

## المستوى 3 — قويّة لكن أثقل/اقتحامية (جهد أكبر، تشغيل المالك)
| الأداة | ⭐ | يسدّ | ملاحظة |
|---|---|---|---|
| **sqlmapproject/sqlmap** | 38k | **SQLi مرجعي** (تأكيد فعلي + استخراج) | Python + اقتحامي → يشغّله المالك على staging |
| **zaproxy/zaproxy** | 15.6k | DAST كامل (baseline/full) | Java ثقيل؛ عبر Docker/API (كان مذكوراً سابقاً) |
| **s0md3v/XSStrike** | 15k | XSS متقدّم | Python، يتقاطع مع dalfox |
| **epi052/feroxbuster** | 8k | اكتشاف محتوى تعاودي | Rust، يتقاطع مع ffuf |

---

## خطة الدمج الموصى بها (بالأولوية)
1. **الشبكة الداخلية (عميل الديسكتوب):** `naabu` + `dnsx` + `tlsx` + `mapcidr/asnmap` + قوالب nuclei الشبكية → فاحص شبكة حقيقي، ودمج نتائجه في التقارير.
2. **مصداقية الويب (P0/P1):** `httpx` (سبر/تقنيات) + `arjun` (بارامترات → يغذّي فاحصات الحقن) + `kiterunner` (API) + `sqlmap` (تأكيد SQLi، تشغيل المالك).
3. **الأدلّة والأسرار:** `trufflehog` (أسرار محقّقة) + `gowitness` (لقطات PoC).
4. **تقوية OSINT (الموجود):** `dnsx` + `tlsx` + `asnmap` + `uncover` (Shodan/Censys) + `S3Scanner` + `trufflehog`.

> **الأسرع تنفيذاً الآن (كلها Go، نفس نمط nuclei):** httpx، naabu، tlsx، dnsx، asnmap، trufflehog، S3Scanner —
> يمكن إضافتها بالـDockerfile خلال دقائق لكلٍّ، ثم بناء فاحص/وحدة حولها.
