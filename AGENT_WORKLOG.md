# 📓 سجل العمل — ترقية Seku بفاحص أمان الدخول (Brute-force + Username Enumeration)

> ملف دليل حتى تعرف **وين وصلنا** لو رجعت للمشروع لاحقاً. يتحدّث مع كل خطوة.
> آخر تحديث: 2026-08-12.

---

## 🎯 الهدف
إضافة **نقلة نوعية** لفاحص Seku تغطّي الجانب الوحيد الناقص: **اختبار أمان تسجيل الدخول**:
1. اكتشاف صفحات/نقاط الدخول (Laravel / Frappe / WordPress / عام).
2. **اختبار قفل الدخول (rate-limit / lockout)** — هل يتقفّل الدخول بعد عدة محاولات؟
3. **تخمين اعتماد ضعيف/افتراضي** (weak/default credentials) بووردلست واسع.
4. **فحص أسماء المستخدمين (username enumeration)** — هل يكشف النظام الفرق بين مستخدم صحيح وخاطئ؟

الغاية **دفاعية**: تحصين أنظمتنا قبل الإطلاق بدون فاحصين بمبالغ عالية.

---

## 🗺️ خريطة النشر (مهمة جداً)
| العنصر | القيمة |
|---|---|
| الموقع | https://sec.erticaz.com |
| المنتج | **Seku** (باكند Go + فرونت Vite/React) |
| تطبيق Coolify | اسم `vscan-mohesr` — أُعيدت تسميته على GitHub إلى **`seku`** |
| Coolify app UUID | `ivmp7lm9ufgqwjvl0vjvkp0q` (سيرفر 91.109.114.87) |
| مصدر النشر | GitHub `haydary1986/seku` فرع `main`، بناء عبر **Dockerfile** |
| النسخة المحلية | `/Users/hayda/Documents/vscaner` (متزامنة مع origin/main) |
| **مسار التحديث** | عدّل محلياً → `git push` إلى `seku:main` → Coolify يعيد النشر |

> ⚠️ الأسرار (توكن Coolify، باسوردات) **لا تُكتب هنا** — هذا الملف يُدفع للريبو العام.

---

## 🏗️ معمارية الفاحص (ما تعلّمناه)
- كل فاحص يطبّق واجهة `Scanner` في `backend/internal/scanner/`:
  ```go
  type Scanner interface {
      Name() string
      Category() string
      Weight() float64
      Scan(url string) []models.CheckResult
  }
  ```
- التسجيل في `allScanners()` داخل `backend/internal/scanner/scanner.go`.
- الأصناف المسموحة لكل خطة في `PlanScanners` (free/starter/basic/pro/enterprise).
- سياسات الفحص في `ScanPolicies` (light/standard/**deep**).
- النتيجة `models.CheckResult`: `Category, CheckName, Status, Score(0-1000), Weight, Severity, Details(JSON), OWASP, CWE, CVSS...`.
- أدوات مشتركة: `ScanTransport` (عميل HTTP فيه rate-limit لكل مضيف + UA متصفّح)، `ensureHTTPS()`, `toJSON()`, `extractHost()`.
- الأداة أصلاً فيها **37 فاحص** (SSL، هيدرز، CORS، SQLi، SSRF، WordPress، XSS، secrets...) لكن **لا يوجد** فاحص دخول/بروتفورس.

---

## 🔒 التصميم الأخلاقي (بوابة الإذن) — إلزامي
الفاحص يستقبل `url` فقط، فبوابة الإذن تُقرأ من متغيّرات البيئة:
- `SEKU_ENABLE_ACTIVE_LOGIN_TEST=1` — تفعيل الاختبار الفعّال (افتراضي: مطفأ).
- `SEKU_LOGIN_TEST_ALLOWLIST="ums.erticaz.com,*.uoturath.edu.iq,..."` — قائمة المضيفين المسموح اختبارهم فعلياً.

**السلوك:**
- على أي هدف: **كشف سلبي فقط (GET)** — إيجاد صفحة الدخول + فحص هيدرز الأمان عليها + إشارات MFA. لا إرسال اعتمادات.
- **الإرسال الفعّال (POST محاولات دخول)** — قفل الدخول + تخمين ضعيف + username-enum — يعمل **فقط** إذا الهدف ضمن allowlist والتفعيل مضبوط. غير ذلك → نتيجة info: «تخطّي — يتطلّب إذناً».
- المحاولات **محدودة ومضبوطة** (cap صغير + rate-limit)، غير مخرّبة، بلا تهرّب من الكشف.

هذا يطابق قاعدتنا: **افحص فقط ما تملكه أو لديك إذن مباشر له**.

---

## ✅ التقدّم (checklist)
- [x] اكتشاف خريطة النشر (Coolify + الريبو).
- [x] فهم معمارية الفاحص والواجهة.
- [x] كتابة ملف الدليل هذا.
- [x] فاحص `login_scanner.go` (اكتشاف + قفل + تخمين + username-enum) مع بوابة الإذن.
- [x] ووردلست مضمّنة (`go:embed`) + override لقوائم كبيرة (rockyou).
- [x] ربط الفاحص في `allScanners()` + سياسة `deep` + خطط pro/business/enterprise.
- [x] بناء الباكند `go build ./...` ناجح (`build_exit=0`, `vet_exit=0`).
- [x] دمج **nuclei** (فاحص `nuclei` عبر binary + Dockerfile) — بناء ناجح، بلا تبعيات جديدة.
- [ ] تحديث `docs/SCANNERS.md` بالفاحصين الجديدين.
- [ ] **تأكيد المستخدم** ثم النشر: `git push seku main` → Coolify redeploy.

---

## 📌 ملاحظات / قرارات
- 2026-08-12: sec.erticaz.com ليس موثّقاً في ڤولت الاعتمادات؛ اكتُشف عبر Coolify API (قراءة فقط).
- 2026-08-12: النسخة المحلية ريموتها `seku` وهو نفس `vscan-mohesr` بعد إعادة التسمية (GitHub redirect).

---

## ✅ ما أُنجز (2026-08-12)
**ملف جديد:** `backend/internal/scanner/login_scanner.go` — فاحص `login` (Weight 12) بأربع فحوص:
| CheckName | نوع | ماذا يفحص | Severity عند الفشل |
|---|---|---|---|
| Login Endpoint Discovery | سلبي (GET) | يكتشف صفحة الدخول ونوعها (laravel/frappe/wordpress/generic) | info |
| Login Transport Security | سلبي (GET) | هل الدخول متاح عبر HTTP صريح؟ | high (A02/CWE-319) |
| Multi-Factor Authentication | سلبي | مؤشرات MFA على صفحة الدخول | info |
| Account Lockout Protection | **فعّال** (POST) | هل يوجد قفل/rate-limit بعد محاولات فاشلة؟ | high (A07/CWE-307) |
| Username Enumeration | **فعّال** (POST) | هل يكشف الفرق بين مستخدم صحيح/خاطئ؟ | medium (A07/CWE-204) |
| Weak or Default Credentials | **فعّال** (POST) | تخمين اعتماد ضعيف/افتراضي (capped) | critical (A07/CWE-1392) |

- بوابة الإذن عبر البيئة (الفحص الفعّال مطفأ افتراضياً) — انظر أدناه.
- ووردلست مضمّنة: `backend/internal/scanner/wordlists/{users,passwords}.txt` (95 مستخدم / 180 كلمة مرور) + override لقوائم كبيرة.
- OWASP/CWE/CVSS/Confidence مسجّلة عبر `init()` (بدون لمس cvss.go/owasp.go/confidence.go).
- ربط: `allScanners()` + سياسة `deep` + خطط `pro/business/enterprise`.

## 🔧 تفعيل الفحص الفعّال (على أنظمتك فقط)
متغيّرات بيئة في تطبيق Coolify (Seku):
```
SEKU_ENABLE_ACTIVE_LOGIN_TEST=1
SEKU_LOGIN_TEST_ALLOWLIST=ums.erticaz.com,*.uoturath.edu.iq,sec.erticaz.com
# اختياري:
SEKU_LOGIN_MAX_ATTEMPTS=30
SEKU_LOGIN_USERS_FILE=/data/wordlists/users-large.txt
SEKU_LOGIN_PASS_FILE=/data/wordlists/rockyou.txt
```
بدونها: الفحص الفعّال **يُتخطّى** ويظهر «authorization required». القوائم الكبيرة تُجلب عبر
`security-scanner/wordlists/fetch-large.sh` (rockyou + SecLists) وتُربط كـ volume.

## 🔎 بحث GitHub — أدوات للتكامل (موصى بها)
| # | الأداة | ★ | القيمة | كيف نكاملها في Seku (Go) |
|---|---|---|---|---|
| 1 | **projectdiscovery/nuclei** + nuclei-templates | 30k+12k | **الأقوى**: آلاف قوالب CVE/إعداد + **244 قالب default-logins** | SDK رسمي `nuclei/v3/lib` (`NewNucleiEngine`) — فاحص `nuclei` داخل العملية، أو binary في Dockerfile |
| 2 | **projectdiscovery/katana** | 17k | زحف/كراول لاكتشاف نماذج ومعاملات أكثر | مكتبة Go → تغذّي بقية الفواحص بروابط |
| 3 | **projectdiscovery/interactsh** | 4.5k | تأكيد OOB للثغرات العمياء (SSRF/XSS/RCE) | مكتبة client Go → يرفع دقّة BlindSQLi/SSRF الموجودة |
| 4 | **projectdiscovery/httpx** + **naabu** | 10k+6k | فحص HTTP/بورتات أسرع وأدق | مكتبات Go → ترقية port/tech scanners |
| 5 | **projectdiscovery/subfinder** + dnsx/shuffledns | 14k | تعداد subdomains سلبي واسع | مكتبة Go → ترقية subdomain scanner |
| 6 | **danielmiessler/SecLists** | — | قوائم ضخمة (rockyou/usernames/paths) | override للووردلست عبر volume (منجز جزئياً) |
| — | google/osv-scanner · anchore/grype | 10k/12k | فحص تبعيات (SCA) — مفيد لوضع CLI | binary في مسار الكود المصدري |

**التوصية:** الأولوية القصوى **nuclei عبر الـ SDK** كفاحص `nuclei` جديد — قفزة تغطية هائلة وتكامل نظيف مع بوابات الإذن نفسها. ثم interactsh لرفع دقّة الفحوص العمياء.

## 🚀 خطوات النشر (تحتاج تأكيد)
1. `cd /Users/hayda/Documents/vscaner && git add -A && git commit -m "feat(scanner): add login security scanner (lockout/brute/username-enum, gated)"`
2. `git push origin main`  (الريبو `haydary1986/seku` = `vscan-mohesr`)
3. Coolify يعيد النشر تلقائياً (أو Trigger عبر API للتطبيق `ivmp7lm9ufgqwjvl0vjvkp0q`).
4. أضف متغيّرات البيئة أعلاه في Coolify ثم Redeploy.

---

## ⚡ دمج nuclei (2026-08-12)
**ملف جديد:** `backend/internal/scanner/nuclei_scanner.go` — فاحص `nuclei` (Weight 15).
- **الطريقة:** يستدعي binary `nuclei` ويقرأ JSONL (بدل SDK الثقيل) → **go.mod ما تغيّر**، والقوالب تُدار بالـ Dockerfile.
- **يتدهور بلطف:** لو الـ binary/القوالب غير موجودة → نتيجة info بدل ما ينكسر الفحص.
- **Dockerfile:** مرحلة `nuclei-builder` (`go install ...nuclei/v3@v3.11.1` + `-update-templates`)، وتُنسخ للصورة النهائية (`/usr/local/bin/nuclei` + `/root/nuclei-templates`).
- كل نتيجة nuclei → `CheckResult` مع severity/score/CVSS من nuclei نفسه، + نتيجة ملخّص «Nuclei Template Scan».
- مربوط: `allScanners()` + `deep` + خطط pro/business/enterprise + عنوان بالفرونت.

**تفعيله (opt-in لأنه ثقيل):**
```
SEKU_ENABLE_NUCLEI=1
# اختياري:
SEKU_NUCLEI_SEVERITY=low,medium,high,critical
SEKU_NUCLEI_TAGS=cve,default-login,exposure,misconfig
SEKU_NUCLEI_RATE=150
SEKU_NUCLEI_TIMEOUT=120
SEKU_NUCLEI_MAX_RESULTS=100
```
بدون `SEKU_ENABLE_NUCLEI=1` → يُتخطّى مع رسالة info.

**عدد الفواحص الآن: 39** (37 أصلي + login + nuclei). البناء: `build_exit=0`, `vet_exit=0`.

---

## 🕸️ دمج katana — الزحف وخريطة سطح الهجوم (2026-08-12)
**ملف جديد:** `backend/internal/scanner/crawl_scanner.go` — فاحص `crawl` (Weight 8).
- يستدعي binary `katana` (نفس نمط nuclei: exec + JSONL مع fallback لنص URL) — بلا تبعيات جديدة.
- يزحف الهدف ويطلّع: عدد الروابط، الروابط ذات المعاملات، و**نقاط حسّاسة مكشوفة** (`.git`/`.env`/admin/phpmyadmin/actuator/graphql/swagger/backup/console...).
- نتيجتان: «Attack Surface Map» (info) و«Sensitive Endpoints Exposed» (تحذير/فشل حسب الخطورة).
- **opt-in:** `SEKU_ENABLE_KATANA=1` (+ `SEKU_KATANA_DEPTH/TIMEOUT/MAX_URLS`). بدونها → info.
- Dockerfile: `go install ...katana@latest` بمرحلة nuclei-builder + نسخ للصورة.
- اختبارات وحدة: تحليل JSONL/نص + gate. مربوط بالسجل + deep + pro/business/enterprise + الفرونت.

**عدد الفواحص الآن: 40** (login + nuclei + crawl). `build/vet/test = 0`. go.mod بلا تغيير.

---

## 📡 دمج interactsh — تأكيد OOB للثغرات العمياء (2026-08-12)
**ملف جديد:** `backend/internal/scanner/oob_scanner.go` — فاحص `oob` (Weight 10).
- **الطريقة:** استخدم interactsh **client SDK** (مو binary) لأن التطابق يحتاج جلسة داخل العملية. مستقل تماماً — **ما لمست** فواحص SSRF/BlindSQLi (صفر خطر انحدار).
- يفتح جلسة interactsh (خوادم `oast.*` الافتراضية)، يحقن `?param=http://<id>.oast.pro` بـ ~25 معامل SSRF شائع، ينتظر الـ callbacks، ويطابق عبر `FullId/UniqueID`.
- **لو وصل تفاعل → Blind SSRF مؤكّد (critical, CVSS 9.1, confidence 99)** — قرب-صفر false positive. يتدهور بلطف لو ما وصل خادم interactsh.
- **opt-in:** `SEKU_ENABLE_OOB=1` (+ `SEKU_INTERACTSH_SERVER/TOKEN`, `SEKU_OOB_MAX_PARAMS`, `SEKU_OOB_WAIT`).
- اختبارات: gate + stripURLQuery. مربوط بالسجل + deep + الخطط + الفرونت.

> ⚠️ **مقايضة:** interactsh SDK (v1.3.1) أضاف **تبعيات كثيرة** لـ go.mod (على عكس nuclei/katana اللي بقوا binaries). البناء ينجح، وبناء Docker يفلتر تبعيات macOS. زمن البناء وحجم الحاوية يزيدان قليلاً — مقبول مقابل تأكيد OOB.
> **متطلّب شبكي:** لازم الحاوية تكدر تطلع لـ `oast.*` (DNS/HTTP) حتى يشتغل الـ polling.

**عدد الفواحص الآن: 41** (login + nuclei + crawl + oob). `build/vet/test = 0`.

### الخطوة التالية المقترحة (interactsh — مرحلة أعمق، اختيارية)
حقن payload الـ OOB **داخل** فاحصي SSRF/BlindSQLi الموجودين (مو فقط فاحص oob المستقل) لرفع دقّتهما — يتطلّب تعديل داخلي محسوب.

---

## 🎨 مراجعة الواجهة (UX) — 2026-08-12
الواجهة Vue ناضجة (26 صفحة). مسار الفحص: Targets → Scans (اختيار سياسة light/standard/deep + أهداف + Start). النتائج بـ ResultDetail مجمّعة حسب الصنف.

**مكاسب سريعة طُبّقت الآن:**
- أضفت عنوان صنف `nuclei` (كان ناقص) + `login/crawl/oob` لخريطة `categoryLabels`.
- حدّثت بطاقة «Deep» ووصف سياسة deep ليذكرا القدرات الجديدة (40 صنف).

**فجوات UX (مرتّبة):**
| الأولوية | الفجوة | التوصية |
|---|---|---|
| 🔴 عالية | الفواحص الأربعة الجديدة «خفية»: تعمل فقط بـ deep + متغيّرات بيئة الباكند؛ المستخدم ما يدري عنها | **مفاتيح لكل فحص** بنموذج البدء (Advanced: ☐login ☐nuclei ☐crawl ☐oob) تُمرّر عبر `startScan` → الباكند يقرأها per-scan بدل env فقط |
| 🟠 متوسطة | لا إقرار إذن للفحوص الفعّالة بالواجهة | صندوق «أُقرّ أني مخوّل بفحص هذا الهدف» + عرض allowlist قبل تفعيل login-brute/oob |
| 🟠 متوسطة | إعدادات المشغّل (env) غير مرئية | قسم بصفحة **Settings** (admin) لتفعيل/إطفاء + allowlist + عتبات nuclei/katana |
| 🟡 منخفضة | أعداد الأصناف مكتوبة يدوياً بالبطاقات (drift) | اشتقاقها من `/scan-policies` |
| 🟡 منخفضة | النصوص الجديدة إنجليزية فقط | إضافة ترجمات AR بـ i18n |

## 🧰 خارطة أدوات إضافية (مثل nuclei) — موصى بها
| الأداة | القيمة | الدمج | التوصية |
|---|---|---|---|
| **dalfox** | فحص XSS متقدّم (DOM/مخزّن/param-mining + تأكيد) | binary + JSON، بلا تبعيات | ⭐ التالي |
| **ffuf / feroxbuster** | اكتشاف محتوى/مجلدات مخفية (قدرة جديدة) | binary | ⭐ التالي |
| **tlsx** (PD) | تحليل TLS/شهادات عميق (يرقّي SSL) | binary | جيد |
| **httpx** (PD) | فحص HTTP/tech/CDN سريع يغذّي البقية | binary | جيد |
| **subfinder** (PD) | تعداد subdomains سلبي واسع (يرقّي الموجود) | binary | متوسط (تداخل) |
| **sqlmap** | استغلال SQLi عميق | binary (Python بالصورة) | ثقيل |
| **wpscan** | WordPress عميق | binary (Ruby) | تداخل مع wp_deep |

**التوصية:** التالي **dalfox + ffuf** (قدرة جديدة/مرقّاة، دمج نظيف بلا تضخيم تبعيات).

---

## 🧩 جلسة التوسّع (2026-08-12) — مفاتيح per-scan + dalfox + ffuf + أداة nuclei

### 1) مفاتيح Advanced في الواجهة (per-scan) — بلا لمس الـ37 فاحص
- ملف `backend/internal/scanner/scan_config.go`: `ScanConfig` + واجهة اختيارية `ConfigurableScanner` + `Engine.WithConfig`.
- المحرّك: `runScannerBounded(s, url, cfg)` يستدعي `ScanWithConfig` إن توفّرت، وإلا `Scan`.
- الفواحص الأربعة (login/nuclei/crawl/oob) صار عندها `ScanWithConfig` تقرأ per-scan **أو** البيئة.
- المعالج `StartScan` يمرّر `ScanConfig` من الطلب. الفرونت `Scans.vue`: قسم **Advanced** (يظهر مع deep) + **إقرار إذن** (إلزامي لـ login-brute) + زر البدء يتعطّل بدون الإقرار.
- **أمان موجود مسبقاً:** الفحص يتطلّب **تحقق ملكية الدومين** لغير الأدمن — فالتفعيل per-scan آمن.

### 2) dalfox (XSS متقدّم) + ffuf (اكتشاف محتوى) — 43 فاحص
- `dalfox_scanner.go` (صنف `xss_advanced`) و `ffuf_scanner.go` (صنف `content_discovery`) — نمط binary+JSON، بلا تبعيات جديدة.
- ffuf يستعمل قائمة مسارات مضمّنة `wordlists/content.txt` (تُكتب لملف مؤقت وقت التشغيل).
- Dockerfile: `go install dalfox + ffuf` ونسخهما. ScanConfig + الخطط + الواجهة + مفاتيح Advanced محدّثة.
- opt-in: `SEKU_ENABLE_DALFOX=1` / `SEKU_ENABLE_FFUF=1` أو مفاتيح per-scan.

### 3) واجهة مخصّصة لـ nuclei (فحص URL/IP واحد) — admin
- الباكند: `POST /api/tools/nuclei` (admin فقط) → `scanner.RunNucleiAdHoc(target, severity, tags)` (أعيد هيكلة nuclei: `run(...,severity,tags)` + `assemble()`).
- الفرونت: صفحة `views/NucleiTool.vue` بمسار `/tools/nuclei` (admin)، رابط بالقائمة الجانبية «Nuclei Scan»، إدخال هدف + severities + tags + عرض النتائج بشارات خطورة.

**الحصيلة:** **43 فاحص** · `go build/vet/test = 0` · الفرونت يبني نظيف. لسّه ما نشرت.

### 4) ووردلست أشمل (بحث GitHub + دمج)
**بحث GitHub:** الأفضل = **danielmiessler/SecLists** (المعيار) + **six2dez/OneListForAll** («rockyou للـ web fuzzing»، 3.2k★). (بدائل: dirsearch، Probable-Wordlists، kkrypt0nn/wordlists.)
**الدمج (تُخبز بصورة Docker، تُضبط كافتراضي عبر ENV، مع fallback للمضمّنة):**
| الاستخدام | القائمة | المصدر | الحجم |
|---|---|---|---|
| اكتشاف محتوى (ffuf) افتراضي | `content.txt` | SecLists `Discovery/Web-Content/common.txt` | ~4,700 |
| اكتشاف محتوى شامل | `content-large.txt` | OneListForAll `onelistforallmicro.txt` | ~40k |
| باسوردات الدخول | `passwords.txt` | SecLists `10k-most-common.txt` | 10,000 |
| أسماء مستخدمين | `users.txt` | SecLists `top-usernames-shortlist` + `cirt-default-usernames` | ~350 |

- Dockerfile: تنزيل بمرحلة `nuclei-builder` (curl) → `/app/wordlists/` + `ENV SEKU_FFUF_WORDLIST/SEKU_LOGIN_PASS_FILE/SEKU_LOGIN_USERS_FILE`.
- مرونة: login `loadList` و ffuf يتجاهلان القائمة المخبوزة لو مفقودة/فارغة ويرجعان للمضمّنة.
- للأشمل يدوياً: `SEKU_FFUF_WORDLIST=/app/wordlists/content-large.txt` أو `SEKU_LOGIN_PASS_FILE` لقائمة أكبر (مع رفع `SEKU_LOGIN_MAX_ATTEMPTS`).
- القوائم المضمّنة الأصلية (95/180/130) تبقى fallback محلي.

**الحصيلة النهائية:** 43 فاحص + ووردلست شاملة + `build/vet/test = 0`.

---

## 🚀 النشر (2026-08-12) — ✅ حي
- Commit `15c0b8f` (الميزات) + `438cfc1` (إصلاح Docker) → push إلى `haydary1986/seku:main`.
- **فشل أول محاولة:** `nuclei v3.11.1 يتطلّب Go ≥ 1.26` بينما `nuclei-builder` كان `golang:1.25-alpine`.
  **الإصلاح:** رفعت مرحلة بناء الأدوات إلى `golang:alpine` (أحدث Go)، مستقلة عن backend-builder (يبقى 1.25، مطابق go.mod).
- إعادة النشر الثانية عبر Coolify API (`GET /deploy?uuid=ivmp7lm9ufgqwjvl0vjvkp0q&force=true`) → **finished** خلال ~3 دقائق.
- **تحقق حي:** `https://sec.erticaz.com/` = 200، `/health` = 200، المسار الجديد `/api/tools/nuclei` = 401 (موجود، admin-gated).

> **درس للمستقبل:** أدوات ProjectDiscovery الحديثة تتطلّب Go جديد — أبقِ `nuclei-builder` على `golang:alpine`.
> **تشغيل الميزات:** الفحوص الفعّالة تبقى مطفأة حتى تفعّلها (مفاتيح Advanced per-scan بالواجهة، أو متغيّرات `SEKU_ENABLE_*` بـ Coolify). أداة nuclei المخصّصة: سجّل دخول admin → `/tools/nuclei`.

### 🐞 إصلاح: «No nuclei template matched» (2026-08-12)
- **السبب:** خطوة `nuclei -update-templates -disable-update-check` بالبناء طبعت البانر وخلصت بـ 0.3s **بلا تنزيل** → مجلد قوالب فارغ → صفر تطابق دائماً.
- **الإصلاح (commit `3cd18bc`):** `git clone --depth 1` لمستودع `nuclei-templates` مباشرة (بلا `|| true` حتى ما يشحن فارغاً بصمت) + `ENV SEKU_NUCLEI_TEMPLATES_DIR=/root/nuclei-templates`.
- **تحقق حيّ داخل الحاوية:** `template_yaml_files=13,530` · nuclei/dalfox/ffuf/katana موجودة · wordlists content=4751 pass=10000 users=845. ✅

---

## 🔧 إصلاحات المشاكل (2026-08-12) — ✅ حي
1. **سقف الوقت لكل فاحص:** كان `const scannerTimeout = 60s` يبتر الفواحص الثقيلة → صار `var` من `SEKU_SCANNER_TIMEOUT` (افتراضي 240s).
2. **بيانات الداشبورد الحقيقية:** `Dashboard.vue` كان يفبرك أرقام الأصناف → صار يستعمل `category_averages` الحقيقية من `/dashboard/enhanced`.
3. **Triage للنتائج:** `TriageStatus/TriageNote` بـ `CheckResult` + `PUT /results/checks/:id/triage` (org-scoped) + قائمة بالواجهة. الحالة v1 مرتبطة بصف الفحص.
- النظام أصلاً عنده SARIF + GitHub/Jira issues + compliance + remediation. الفجوة الكبرى الباقية: **الفحص المُصادَق** (لاحقاً).

---

## 💳 تحوّل SaaS: دفع لكل فحص عميق (2026-08-15) — ✅ منشور

**القرار (بموافقة المستخدم عبر AskUserQuestion):** الفحص الخفيف مجاني للجميع، الفحص العميق مدفوع **لكل فحص/نطاق** عبر **حوالة داخلية يدوية**. تم إلغاء طبقات الدولار الست (كانت وهمية)؛ بقي نموذجان: مجاني (خفيف) + عميق بالدفع. السعر الافتراضي **25,000 د.ع** (قابل للتعديل من الإعدادات).

**كان موجوداً أصلاً (~70%):** تسجيل عام، منظمات/خطط، تحقق دومين بـ TXT، طلبات ترقية بموافقة أدمن، حدود خطة بـ StartScan، والأدمن يتجاوز التحقق.

**المُضاف:**
- **تحقق بالملف:** `verification.go` صار يجرّب DNS TXT ثم يجيب `https://<domain>/.well-known/seku-verify.txt` (fallback http) ويطابق `vscan-verify=<key>`. حقل `Method` بالنموذج (dns_txt|file). واجهة `Targets.vue` فيها تبويبان (TXT / رفع ملف).
- **نموذج `DeepScanOrder`** (pending→paid→used|rejected) + `orders.go`: إنشاء طلب، إرسال رقم الحوالة، قائمة طلباتي؛ وللأدمن قائمة الكل + تأكيد/رفض. مسارات `/orders*` و `/orders/all` (أدمن).
- **قفل الربح في `StartScan`:** `isDeep = policy==deep || أي أداة نشطة`. غير الأدمن يحتاج **رصيد مدفوع لكل نطاق** (402 يتطلب دفع) ويُستهلك عند التشغيل. السقف الشهري المجاني يطبّق على الخفيف فقط.
- **إعدادات دفع للأدمن** (Settings): `deep_scan_price_iqd`, `payment_method`, `payment_account`, `payment_instructions_ar/en` — لا أسرار بالكود. نقطة عامة `/pricing` (السعر فقط) لصفحة الأسعار.
- **حدود الخطة المجانية رُفعت:** 25 نطاق · 100 فحص خفيف/شهر (بدل 1/5).
- **واجهات:** `Orders.vue` (شراء+دفع للمستخدم)، `AdminOrders.vue` (تأكيد الحوالات)، شارة «مدفوع» على بطاقة الفحص العميق + معالجة 402 مع رابط للطلبات، `Pricing.vue` أُعيدت كطبقتين + «كيف يعمل» + FAQ، بند تنقّل `nav.orders` (يوجّه المستخدم لـ /orders والأدمن لـ /admin/orders).

**تدفّق العميل:** تسجيل → إضافة نطاق → توثيق (TXT/ملف) → طلب فحص عميق → حوالة → إدخال رقم الإشعار → تأكيد الأدمن → تشغيل الفحص العميق.

**قبله (نفس اليوم):** إصلاح الجلسة المنزلقة `/auth/refresh` (تجديد التوكن عند الفتح/كل 6 ساعات/عند الرجوع للتبويب) لإيقاف تسجيل الخروج المفاجئ.

---

## 🛡️ تحصين أمني وموثوقية عبر موجات (2026-08-15) — بعد تدقيق 5 وكلاء

تدقيق متعدد الوكلاء (فحص/SaaS/بنية/أمان/UX) أنتج خارطة بأربع موجات. المُنفَّذ والمنشور:

### الموجة 0 — أمان حرِج (✅ حيّ ومؤكّد)
- **IDOR بين المنظمات**: كل نقاط `:id` (scans/results/pdf/sarif/csv/compliance/fix-priority/ai/compare/history/integrations) صارت مُقيّدة بالملكية عبر حرّاس `CanAccessJob/Result/Target/Check` في `middleware.go`. كان أي مستخدم يقرأ تقارير ثغرات أي منظمة.
- **JWT**: `auth.go` يرفض الإقلاع بسرّ فارغ/افتراضي؛ `ws/hub.go` يفشل مغلقاً. ضُبط `JWT_SECRET` قوي في Coolify (أبطل التوكِنات القديمة).
- **التفاف التحقق + SSRF**: `UpdateTarget` DTO بقائمة سماح (تغيير URL يُبطل التحقق)؛ `StartScan` يعيد مطابقة النطاق ويحظر العناوين الداخلية؛ `schedules.go` + `scheduler.go` بعزل تنظيمي وتحقّق؛ حزمة `internal/safehttp` (حظر loopback/private/link-local/metadata/CGNAT + rebinding + redirects) على تحقق الملف/webhooks/Jira.
- **rate limiting**: `/auth/login`,`/auth/register` (10/د)، AI (20/د) — مؤكَّد حيّاً (429 بعد العاشرة).
- **سباق الرصيد (TOCTOU)**: `consumeDeepScanCredits` معاملة ذرّية بتحديث شرطي — لا فحص عميق مجاني.
- **SQLite WAL** + `busy_timeout` + اتصال كتابة واحد في `config/database.go`.

### الموجة 1 — الثقة/الإيراد + الموثوقية (✅ حيّ)
- **بريد معاملات** لأحداث الطلب (إنشاء/دفع/رفض) + تنبيه المشرف (`services.SendSimpleEmail`/`EmailShell`/`AdminNotifyEmail`).
- **إصلاح الاستئناف**: حقول policy/tools على `ScanJob`؛ الاستئناف بنفس السياسة لا «deep» دائماً.
- **إطفاء رشيق** في `cmd/main.go` (SIGTERM → ShutdownWithTimeout).
- **سقف تزامن كلّي** `SEKU_MAX_CONCURRENT_SCANS=3` (semaphore في `RunScan`) لمنع OOM.
- **رفع إثبات الحوالة** (`/orders/:id/proof`) + عرضه للمشرف.
- مفاتيح API لكل المنظمات (أُزيل تعارض الطبقات)، تصحيح نصّ التسجيل.

### الموجة 2 — قوة الفحص (✅ حيّ)
- **GraphQLScanner** (`graphql_scanner.go`): كشف endpoints + علم introspection المفتوح.
- **JWTScanner** (`jwt_scanner.go`): يلتقط JWT من الكوكيز/الرؤوس/الجسم؛ يكشف `alg:none` وHMAC ضعيف (crack بقائمة) وexp مفقود.
- مُسجَّلان في deep (`graphql`, `jwt_security`).
- ملاحظة: تفعيل nuclei أصلاً يشغّل كل القوالب (CVE/LFI/RCE...) بلا وسم؛ الفجوة المتبقية = fuzzing/DAST بالبارامترات المكتشفة (يعتمد على توصيل الزحف).

### المتبقّي (كبير — يُنصَح به كأعمال لاحقة مركّزة)
- **الفحص المُصادَق** (حقن جلسة) + **IDOR/BOLA تفاضلي** — L لكل منهما، أساس لتغطية ما خلف تسجيل الدخول.
- **الموجة 3 (UX/نمو)**: توصيل i18n (2/31 صفحة تستعمل t())، إصلاح الوضع الداكن (27 صفحة)، نظام toast عام، onboarding، تقرير عام + شارة، فحص فوري على Landing، /docs عامة + GitHub Action، metrics/Postgres.

### الموجة الكبيرة — الفحص المُصادَق + IDOR/BOLA (✅ منشورة، تحقّق حيّ قيد الإكمال)
- **`ScanConfig`**: حقول `AuthCookie`/`AuthHeader`/`AuthCookieB` + `HasAuth`/`applyAuth`/`applyAuthB`/`authToolArgs`.
- **حقن الجلسة** في katana (crawl) وnuclei عبر `-H` → الفحص يصل للصفحات خلف تسجيل الدخول.
- **`AccessControlScanner`** (فئة `access_control`، ضمن deep): يزحف كالمستخدم أ ويجمع روابط الكائنات (مسارات فيها IDs)، ثم يعيد طلب كلٍّ كالمستخدم ب (أو مجهول) ويعلّم الاستجابات المتطابقة تقريباً كمرشّح IDOR/BOLA (ثقة متوسطة + «تحقّق يدوياً»). يخدم مباشرة متطلّب بوابات ERPNext الأربع.
- الحقول تُمرَّر عبر `StartScanRequest → ScanConfig`، وتُحفظ على `ScanJob`، وتُستعاد عند الاستئناف.
- واجهة `Scans.vue`: حقول الفحص المُصادَق (كوكي الجلسة، رأس إضافي، جلسة مستخدم ثانٍ لـ IDOR).

**كيفية الاستخدام:** فحص عميق + الصق كوكي جلسة صالحة (من DevTools) في «فحص مُصادَق». لفحص IDOR: أضف كوكي حساب ثانٍ على نفس النظام.

### المتبقّي (الموجة 3 — UX/نمو، لاحقاً بطلب المستخدم)
توصيل i18n، الوضع الداكن، toast، onboarding، تقرير عام + شارة، فحص فوري على Landing، /docs عامة، metrics.

### الموجة 3 — UX/نمو (دفعات، ✅ منشورة)
**3.1 تقرير عام + شارة:**
- `ScanResult.ShareToken` (اختياري)؛ `POST/DELETE /results/:id/share` (org-scoped).
- عام `GET /public/report/:token` = ملخّص مُنقّى (درجة/تقدير/عدّ الخطورة/فئات pass-fail) بلا تفاصيل حسّاسة.
- عام `GET /public/badge/:token` = شارة SVG قابلة للتضمين ملوّنة حسب التقدير.
- واجهة: صفحة `/r/:token` عامة (بعلامة سيكو + CTA)، وزر «مشاركة عامة» في ResultDetail مع رابط ونسخ كود التضمين.

**3.2 نظام toast عام + /docs عامة:**
- `useToast` composable + `Toast.vue` مُركّب في App.vue (teleport، auto-dismiss، success/error/info).
- رُبط بمشاركة/نسخ ResultDetail كأول متبنّي (بدل alert()).
- `/docs` صارت عامة (تبنّي المطورين + SEO).

**متبقٍّ من الموجة 3 (دفعات لاحقة):** توصيل i18n الكامل (تحويل نصوص 31 صفحة إلى t())، الوضع الداكن عبر كل الصفحات، onboarding/جولة أولى، فحص فوري + تقرير عيّنة على Landing، MS Teams، skeletons، الوصولية. — أعمال ميكانيكية كبيرة عبر ملفات كثيرة، تُنفَّذ تدريجياً.

### الموجة 3 — دفعات UX/نمو عبر وكلاء متوازين (✅ منشورة) — الوضع الداكن مُستثنى بطلب المستخدم
**الدفعة A — توصيل i18n (6 وكلاء متوازين):** حوّلت 10 صفحات مواجهة للعميل إلى `t()` (Login, Register, Dashboard, Scans, ScanDetail, Targets, Orders, AdminOrders, Profile, Leaderboard) — **337 مفتاح** بمساحات per-view. كل وكيل عدّل صفحاته + كتب ملف شذرة، ودُمجت مركزياً في ar.json/en.json (سكربت `merge_i18n.js`). زر اللغة الآن يبدّل هذه الصفحات فعلياً.
**الدفعة B — 3 وكلاء:** (1) تنبيهات **MS Teams** (MessageCard عبر postJSON المحمي + validTypes + Webhooks.vue). (2) **onboarding**: `OnboardingChecklist.vue` (أضف نطاق ← وثّق ← افحص ← اطّلع) على الداشبورد، قابل للإخفاء ويختفي عند الاكتمال + حالات فارغة أفضل في Targets/Scans. (3) **إعادة فحص بنقرة** في ResultDetail.
**الدفعة C — الفحص الفوري على Landing:** نقطة عامة `POST /public/quickscan` (بلا مصادقة، محمية SSRF، rate-limit 3/دقيقة، بلا حفظ) تشغّل فواحص سريعة وترجع درجة/تقدير/ملخّص؛ وصندوق «افحص موقعك الآن» في Landing يعرض بطاقة نتيجة تشويقية + دعوة تسجيل.

**ملاحظة تقنية:** مفاتيح onboarding في ملف شذرة يستورده المكوّن مباشرة (index.js كان خارج نطاق الوكيل) — يعمل؛ يمكن لاحقاً دمجه في القواميس للتوحيد.

### إصلاح واجهة + عطل نشر (2026-08-16)
- **إعادة تنظيم التنقّل** في لوحة التحكم بمجموعات (الرئيسية/التحليل/الأتمتة/الإدارة/الحساب) + **شريط علوي موحّد** (عنوان من الراوتر + ثيم/لغة + قائمة مستخدم)، وإزالة العناوين المكرّرة من 23 صفحة (عبر 6 وكلاء).
- **تصفّح وأنت مسجّل** مسموح (أُزيل تحويل landing→dashboard القسري) + زر «لوحتي».
- **هيدر عام موحّد `PublicHeader`** لكل الصفحات العامة (Landing/Pricing/Methodology/Docs/Downloads) — أُزيلت قائمة Landing الخاصة فصار الجميع على قائمة واحدة.
- 🔴 **عطل نشر مهم اكتُشف وحُلّ:** كان Cloudflare يخزّن **404 لأصل الـJS** إذا وصله طلب أثناء لحظة تبديل حاوية Coolify (cf-cache-status: HIT على 404) → الـSPA لا يُحمّل والموقع يبدو «قديم/بلا قائمة». الحل الفوري: تغيير بصمة الحزمة (build stamp في main.js) → اسم أصل جديد لا يوجد له 404 مخزّن. **درس دائم:** بعد كل نشر، إمّا تفريغ كاش Cloudflare أو قاعدة تمنع تخزين 4xx لملفات `/assets`، أو انتظار جاهزية الحاوية قبل توجيه الترافيك.
