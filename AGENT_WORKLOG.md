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

**الحصيلة النهائية:** 43 فاحص + ووردلست شاملة + `build/vet/test = 0`. لسّه ما نشرت.
