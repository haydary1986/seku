package api

import (
	"github.com/gofiber/fiber/v2"

	"seku/internal/scanner"
)

// CategoryInfo maps category ID to display name
var categoryDisplayNames = map[string]string{
	"ssl":               "SSL/TLS Encryption",
	"headers":           "Security Headers",
	"cookies":           "Cookie Security",
	"server_info":       "Server Information",
	"directory":         "Directory & Files",
	"performance":       "Performance",
	"ddos":              "DDoS Protection",
	"cors":              "CORS Configuration",
	"http_methods":      "HTTP Methods",
	"dns":               "DNS Security",
	"mixed_content":     "Mixed Content",
	"info_disclosure":   "Information Disclosure",
	"content":           "Content Optimization",
	"hosting":           "Hosting Quality",
	"advanced_security": "Advanced Security",
	"malware":           "Malware & Threats",
	"threat_intel":      "Threat Intelligence",
	"seo":               "SEO & Technical Health",
	"third_party":       "Third-Party Scripts Risk",
	"js_libraries":      "JavaScript Libraries",
}

func GetPlans(c *fiber.Ctx) error {
	type PlanCategory struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	type Plan struct {
		ID              string         `json:"id"`
		Name            string         `json:"name"`
		NameAr          string         `json:"name_ar"`
		Tagline         string         `json:"tagline"`
		TaglineAr       string         `json:"tagline_ar"`
		Price           string         `json:"price"`
		PriceMonthly    int            `json:"price_monthly"`
		PriceYearly     int            `json:"price_yearly"`
		MaxTargets      int            `json:"max_targets"`
		MaxScansMonth   int            `json:"max_scans_month"`
		MaxUsers        int            `json:"max_users"`
		AIAnalysis      string         `json:"ai_analysis"`
		PDFReports      bool           `json:"pdf_reports"`
		ScheduledScans  string         `json:"scheduled_scans"`
		APIAccess       string         `json:"api_access"`
		EmailAlerts     bool           `json:"email_alerts"`
		WebhookAlerts   bool           `json:"webhook_alerts"`
		WAFDashboard    bool           `json:"waf_dashboard"`
		DataLeakScan    bool           `json:"data_leak_scan"`
		Discovery       bool           `json:"discovery"`
		Directives      bool           `json:"directives"`
		HistoryDays     int            `json:"history_days"`
		Support         string         `json:"support"`
		CategoryCount   int            `json:"category_count"`
		Categories      []PlanCategory `json:"categories"`
		TotalCategories int            `json:"total_categories"`
		Popular         bool           `json:"popular"`
		Features        []string       `json:"features"`
		FeaturesAr      []string       `json:"features_ar"`
	}

	plans := []Plan{
		{
			ID: "free", Name: "Free", NameAr: "مجاني",
			Tagline: "Try Seku for one website",
			TaglineAr: "جرّب سيكو لموقع واحد",
			Price: "$0", PriceMonthly: 0, PriceYearly: 0,
			MaxTargets: 1, MaxScansMonth: 5, MaxUsers: 1,
			AIAnalysis: "No", PDFReports: false,
			ScheduledScans: "No", APIAccess: "No",
			EmailAlerts: false, WebhookAlerts: false,
			WAFDashboard: false, DataLeakScan: false,
			Discovery: false, Directives: false,
			HistoryDays: 7, Support: "Community",
			Features: []string{
				"1 website",
				"5 scans per month",
				"5 basic security categories",
				"7 days scan history",
				"Community support",
			},
			FeaturesAr: []string{
				"موقع واحد",
				"5 فحوصات شهرياً",
				"5 فئات أمان أساسية",
				"سجل الفحوصات لـ 7 أيام",
				"دعم مجتمعي",
			},
		},
		{
			ID: "starter", Name: "Starter", NameAr: "ابتدائي",
			Tagline: "For freelancers and small business websites",
			TaglineAr: "للمطورين والمواقع التجارية الصغيرة",
			Price: "$49/mo", PriceMonthly: 49, PriceYearly: 490,
			MaxTargets: 5, MaxScansMonth: 25, MaxUsers: 2,
			AIAnalysis: "10/month", PDFReports: true,
			ScheduledScans: "Weekly", APIAccess: "No",
			EmailAlerts: true, WebhookAlerts: false,
			WAFDashboard: false, DataLeakScan: false,
			Discovery: false, Directives: false,
			HistoryDays: 30, Support: "Email (72h response)",
			Features: []string{
				"5 websites",
				"25 scans per month",
				"13 security categories",
				"PDF reports (Arabic + English)",
				"AI analysis (10/month)",
				"Weekly scheduled scans",
				"Email alerts",
				"30 days scan history",
				"Email support",
			},
			FeaturesAr: []string{
				"5 مواقع",
				"25 فحص شهرياً",
				"13 فئة أمان",
				"تقارير PDF بالعربية والإنجليزية",
				"تحليل AI (10 شهرياً)",
				"فحص أسبوعي مجدول",
				"تنبيهات بالبريد",
				"سجل لـ 30 يوم",
				"دعم بالبريد الإلكتروني",
			},
		},
		{
			ID: "basic", Name: "Basic", NameAr: "أساسي",
			Tagline: "For small universities and colleges",
			TaglineAr: "للكليات الأهلية والمؤسسات التعليمية الصغيرة",
			Price: "$149/mo", PriceMonthly: 149, PriceYearly: 1490,
			MaxTargets: 15, MaxScansMonth: 100, MaxUsers: 5,
			AIAnalysis: "Unlimited", PDFReports: true,
			ScheduledScans: "Daily", APIAccess: "Read-only",
			EmailAlerts: true, WebhookAlerts: true,
			WAFDashboard: false, DataLeakScan: false,
			Discovery: false, Directives: false,
			HistoryDays: 180, Support: "Priority email (24h response)",
			Features: []string{
				"15 websites",
				"100 scans per month",
				"22 security categories",
				"PDF reports + custom branding",
				"Unlimited AI analysis",
				"Daily scheduled scans",
				"Webhooks (Slack/Telegram)",
				"Read-only API access",
				"180 days scan history",
				"Priority email support (24h)",
			},
			FeaturesAr: []string{
				"15 موقعاً",
				"100 فحص شهرياً",
				"22 فئة أمان",
				"تقارير PDF بشعارك الخاص",
				"تحليل AI غير محدود",
				"فحص يومي مجدول",
				"Webhooks (Slack/Telegram)",
				"وصول API للقراءة",
				"سجل لـ 180 يوم",
				"دعم سريع بالبريد (24 ساعة)",
			},
		},
		{
			ID: "pro", Name: "Pro", NameAr: "احترافي",
			Tagline: "Most popular — for medium universities",
			TaglineAr: "الأكثر شعبية — للجامعات الأهلية المتوسطة",
			Price: "$499/mo", PriceMonthly: 499, PriceYearly: 4990,
			MaxTargets: 50, MaxScansMonth: 500, MaxUsers: 15,
			AIAnalysis: "Unlimited", PDFReports: true,
			ScheduledScans: "Daily", APIAccess: "Full",
			EmailAlerts: true, WebhookAlerts: true,
			WAFDashboard: true, DataLeakScan: true,
			Discovery: true, Directives: false,
			HistoryDays: 365, Support: "Priority + chat (8h response)",
			Popular: true,
			Features: []string{
				"50 websites",
				"500 scans per month",
				"28 advanced security categories",
				"Unlimited AI analysis",
				"Daily scheduled scans",
				"Full API + all Webhooks",
				"Domain Discovery (find hidden sites)",
				"Data Leak Scanner (HIBP integration)",
				"WAF Dashboard integration",
				"GitHub/Jira issue creation",
				"1 year scan history",
				"Priority support (8h response)",
			},
			FeaturesAr: []string{
				"50 موقعاً",
				"500 فحص شهرياً",
				"28 فئة أمان متقدمة",
				"تحليل AI غير محدود",
				"فحص يومي مجدول",
				"API كامل + جميع الـ Webhooks",
				"اكتشاف النطاقات المخفية",
				"فحص تسريب البيانات (HIBP)",
				"لوحة WAF متكاملة",
				"إنشاء تذاكر GitHub/Jira",
				"سجل فحوصات لسنة كاملة",
				"دعم سريع (خلال 8 ساعات)",
			},
		},
		{
			ID: "business", Name: "Business", NameAr: "أعمال",
			Tagline: "For large universities and corporate clients",
			TaglineAr: "للجامعات الكبرى والشركات",
			Price: "$1,499/mo", PriceMonthly: 1499, PriceYearly: 14990,
			MaxTargets: 200, MaxScansMonth: 2000, MaxUsers: 50,
			AIAnalysis: "Unlimited", PDFReports: true,
			ScheduledScans: "Hourly", APIAccess: "Full + SLA",
			EmailAlerts: true, WebhookAlerts: true,
			WAFDashboard: true, DataLeakScan: true,
			Discovery: true, Directives: true,
			HistoryDays: 730, Support: "Dedicated CSM + chat (4h response)",
			Features: []string{
				"200 websites",
				"2,000 scans per month",
				"All 32 security categories",
				"Hourly scheduled scans",
				"Administrative Directives generator",
				"Multi-organization management",
				"Custom branding (white-label PDFs)",
				"Compliance reports (GDPR, ISO 27001)",
				"2 years scan history",
				"Dedicated Customer Success Manager",
				"4-hour response SLA",
				"Onboarding & training session",
			},
			FeaturesAr: []string{
				"200 موقع",
				"2,000 فحص شهرياً",
				"جميع الـ 32 فئة أمنية",
				"فحص كل ساعة",
				"مولّد الأوامر الإدارية",
				"إدارة منظمات متعددة",
				"علامة تجارية مخصصة (تقارير بشعارك)",
				"تقارير الامتثال (GDPR, ISO 27001)",
				"سجل فحوصات لسنتين",
				"مدير نجاح عملاء مخصص",
				"استجابة خلال 4 ساعات",
				"جلسة تأهيل وتدريب",
			},
		},
		{
			ID: "enterprise", Name: "Enterprise", NameAr: "مؤسسات حكومية",
			Tagline: "For ministries and government bodies",
			TaglineAr: "للوزارات والجهات الحكومية",
			Price: "From $3,000/mo", PriceMonthly: -1, PriceYearly: -1,
			MaxTargets: 9999, MaxScansMonth: 9999, MaxUsers: 9999,
			AIAnalysis: "Unlimited", PDFReports: true,
			ScheduledScans: "Custom", APIAccess: "Full + Premium SLA",
			EmailAlerts: true, WebhookAlerts: true,
			WAFDashboard: true, DataLeakScan: true,
			Discovery: true, Directives: true,
			HistoryDays: -1, Support: "Dedicated team + 24/7 phone",
			Features: []string{
				"Unlimited websites & scans",
				"All features included",
				"On-premise deployment",
				"Air-gapped installation available",
				"SAML/SSO/LDAP integration",
				"Custom scanner development",
				"Source code access (on request)",
				"Quarterly security review meetings",
				"24/7 phone + dedicated team",
				"99.9% uptime SLA + penalties",
				"Custom contract terms",
				"On-site training & deployment",
			},
			FeaturesAr: []string{
				"مواقع وفحوصات غير محدودة",
				"جميع الميزات مفعّلة",
				"نشر محلي (On-premise)",
				"تنصيب معزول عن الإنترنت متاح",
				"تكامل SAML/SSO/LDAP",
				"تطوير ماسحات مخصصة",
				"الوصول للسورس كود (عند الطلب)",
				"اجتماعات مراجعة أمنية ربع سنوية",
				"دعم 24/7 هاتفياً + فريق مخصص",
				"اتفاقية مستوى خدمة 99.9% + غرامات",
				"شروط عقد مخصصة",
				"تدريب ونشر في موقعكم",
			},
		},
	}

	totalCategories := len(scanner.PlanScanners["enterprise"])

	for i := range plans {
		cats := scanner.GetPlanCategories(plans[i].ID)
		plans[i].CategoryCount = len(cats)
		plans[i].TotalCategories = totalCategories
		for _, catID := range cats {
			name := categoryDisplayNames[catID]
			if name == "" {
				name = catID
			}
			plans[i].Categories = append(plans[i].Categories, PlanCategory{
				ID:   catID,
				Name: name,
			})
		}
	}

	return c.JSON(fiber.Map{
		"plans":            plans,
		"total_categories": totalCategories,
	})
}
