package api

import (
	"github.com/gofiber/fiber/v2"

	"vscan-mohesr/internal/scanner"
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
		Price           string         `json:"price"`
		PriceMonthly    int            `json:"price_monthly"`
		MaxTargets      int            `json:"max_targets"`
		MaxScansMonth   int            `json:"max_scans_month"`
		MaxUsers        int            `json:"max_users"`
		AIAnalysis      string         `json:"ai_analysis"`
		PDFReports      bool           `json:"pdf_reports"`
		ScheduledScans  string         `json:"scheduled_scans"`
		APIAccess       string         `json:"api_access"`
		EmailAlerts     bool           `json:"email_alerts"`
		Support         string         `json:"support"`
		CategoryCount   int            `json:"category_count"`
		Categories      []PlanCategory `json:"categories"`
		TotalCategories int            `json:"total_categories"`
		Popular         bool           `json:"popular"`
	}

	plans := []Plan{
		{
			ID: "free", Name: "Free", NameAr: "مجاني",
			Price: "$0", PriceMonthly: 0,
			MaxTargets: 5, MaxScansMonth: 10, MaxUsers: 1,
			AIAnalysis: "No", PDFReports: false,
			ScheduledScans: "No", APIAccess: "No",
			EmailAlerts: false, Support: "Community",
		},
		{
			ID: "basic", Name: "Basic", NameAr: "أساسي",
			Price: "$29/mo", PriceMonthly: 29,
			MaxTargets: 25, MaxScansMonth: 50, MaxUsers: 5,
			AIAnalysis: "10/month", PDFReports: true,
			ScheduledScans: "Weekly", APIAccess: "Read-only",
			EmailAlerts: true, Support: "Email",
		},
		{
			ID: "pro", Name: "Pro", NameAr: "احترافي",
			Price: "$99/mo", PriceMonthly: 99,
			MaxTargets: 100, MaxScansMonth: 200, MaxUsers: 20,
			AIAnalysis: "50/month", PDFReports: true,
			ScheduledScans: "Daily", APIAccess: "Full",
			EmailAlerts: true, Support: "Priority",
			Popular: true,
		},
		{
			ID: "enterprise", Name: "Enterprise", NameAr: "مؤسسات",
			Price: "Custom", PriceMonthly: -1,
			MaxTargets: 9999, MaxScansMonth: 9999, MaxUsers: 9999,
			AIAnalysis: "Unlimited", PDFReports: true,
			ScheduledScans: "Custom", APIAccess: "Full",
			EmailAlerts: true, Support: "Dedicated",
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
