package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// GenerateSitemap serves a dynamic sitemap.xml.
// Includes static pages — extend with database-backed URLs as needed.
func GenerateSitemap(c *fiber.Ctx) error {
	baseURL := getSetting("seo_site_url")
	if baseURL == "" {
		baseURL = "https://sec.erticaz.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	today := time.Now().Format("2006-01-02")

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")

	pages := []struct {
		path       string
		priority   string
		changefreq string
	}{
		{"/", "1.0", "weekly"},
		{"/pricing", "0.9", "monthly"},
		{"/methodology-ar", "0.8", "monthly"},
		{"/methodology", "0.8", "monthly"},
		{"/register", "0.5", "yearly"},
		{"/login", "0.3", "yearly"},
	}

	for _, p := range pages {
		sb.WriteString(fmt.Sprintf(`  <url>
    <loc>%s%s</loc>
    <lastmod>%s</lastmod>
    <changefreq>%s</changefreq>
    <priority>%s</priority>
    <xhtml:link rel="alternate" hreflang="ar" href="%s%s"/>
    <xhtml:link rel="alternate" hreflang="en" href="%s%s?lang=en"/>
  </url>
`, baseURL, p.path, today, p.changefreq, p.priority, baseURL, p.path, baseURL, p.path))
	}

	sb.WriteString(`</urlset>`)

	c.Set("Content-Type", "application/xml")
	c.Set("Cache-Control", "public, max-age=3600")
	return c.SendString(sb.String())
}

// GenerateRobots serves robots.txt.
func GenerateRobots(c *fiber.Ctx) error {
	baseURL := getSetting("seo_site_url")
	if baseURL == "" {
		baseURL = "https://sec.erticaz.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	// Allow disabling indexing entirely
	if getSetting("seo_disable_indexing") == "true" {
		c.Set("Content-Type", "text/plain")
		return c.SendString("User-agent: *\nDisallow: /\n")
	}

	robots := `User-agent: *
Allow: /
Allow: /pricing
Allow: /methodology
Allow: /methodology-ar

Disallow: /dashboard
Disallow: /targets
Disallow: /scans
Disallow: /results/
Disallow: /leaderboard
Disallow: /upgrade
Disallow: /schedules
Disallow: /api-keys
Disallow: /profile
Disallow: /ai-chat
Disallow: /compare
Disallow: /webhooks
Disallow: /users
Disallow: /settings
Disallow: /subscriptions
Disallow: /discovery
Disallow: /directives
Disallow: /data-leak
Disallow: /api/
Disallow: /ws/

User-agent: Googlebot
Allow: /
Crawl-delay: 1

User-agent: Bingbot
Allow: /
Crawl-delay: 1

User-agent: AhrefsBot
Disallow: /

User-agent: SemrushBot
Disallow: /

Sitemap: ` + baseURL + `/sitemap.xml
`
	c.Set("Content-Type", "text/plain")
	c.Set("Cache-Control", "public, max-age=86400")
	return c.SendString(robots)
}

// GetSEOSettings returns the current SEO configuration.
func GetSEOSettings(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"site_url":           getSettingOr("seo_site_url", "https://sec.erticaz.com"),
		"site_name":          getSettingOr("seo_site_name", "Seku - سيكو"),
		"site_title":         getSettingOr("seo_site_title", "سيكو Seku — فاحص أمان المواقع الإلكترونية"),
		"site_description":   getSettingOr("seo_site_description", "منصة فحص أمان المواقع الإلكترونية الأقوى في العراق. 32 فئة فحص أمني، تقييم من 1000 نقطة، تحليل بالذكاء الاصطناعي."),
		"site_keywords":      getSettingOr("seo_site_keywords", "فحص أمان, vulnerability scanner, سيكو, Seku"),
		"og_image":           getSettingOr("seo_og_image", "https://sec.erticaz.com/og-image.png"),
		"twitter_handle":     getSettingOr("seo_twitter_handle", "@IrtikazTech"),
		"google_analytics":   getSettingOr("seo_google_analytics", ""),
		"google_search_console": getSettingOr("seo_google_search_console", ""),
		"bing_verification":  getSettingOr("seo_bing_verification", ""),
		"facebook_app_id":    getSettingOr("seo_facebook_app_id", ""),
		"disable_indexing":   getSettingOr("seo_disable_indexing", "false"),
		"organization_name":  getSettingOr("seo_org_name", "Irtikaz Technical Solutions"),
		"organization_url":   getSettingOr("seo_org_url", "https://erticaz.com"),
	})
}

// getSettingOr returns the setting value or default if not set.
func getSettingOr(key, defaultVal string) string {
	v := getSetting(key)
	if v == "" {
		return defaultVal
	}
	return v
}
