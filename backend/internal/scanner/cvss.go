package scanner

// CVSSMapping holds the CVSS v3.1 base score, vector string, and qualitative rating for a check
type CVSSMapping struct {
	Score  float64 `json:"cvss_score"`
	Vector string  `json:"cvss_vector"`
	Rating string  `json:"cvss_rating"` // Critical, High, Medium, Low, None
}

// CheckCVSSMap maps check names to their CVSS v3.1 base metrics
var CheckCVSSMap = map[string]CVSSMapping{
	// SSL/TLS
	"HTTPS Enabled":          {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},
	"Certificate Validity":   {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"},
	"TLS Version":            {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},
	"HTTP to HTTPS Redirect": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"},

	// Headers
	"HSTS":                    {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},
	"Content Security Policy": {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},
	"X-Frame-Options":         {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},
	"Permissions-Policy":      {4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "Medium"},

	// XSS
	"Reflected XSS Detection":  {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},
	"DOM-Based XSS Indicators": {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},
	"Input Sanitization Check": {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},

	// Secrets
	"API Key Exposure":                    {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"},
	"Private Key / Certificate Exposure":  {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"},
	"Database Connection String Exposure": {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"},

	// Malware
	"Malicious JavaScript Detection": {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"},
	"Cryptocurrency Miner Detection": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "High"},
	"Hidden Iframe Detection":        {8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High"},

	// Directory
	"Environment File Exposure": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},
	"Git Repository Exposure":   {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},
	"Admin Panel Exposure":      {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"},

	// CORS
	"CORS Wildcard Origin": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},

	// HTTP Methods
	"Dangerous HTTP Methods": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Medium"},

	// DNS
	"DMARC Record (Email Security)": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Medium"},
	"SPF Record (Email Security)":   {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Medium"},

	// WordPress
	"XML-RPC Exposure":          {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "High"},
	"REST API User Enumeration": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"},
	"Debug Mode Detection":      {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},

	// Subdomains
	"Dangling DNS / Subdomain Takeover": {8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N", "High"},

	// SQL Injection
	"SQL Injection Test":        {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"},
	"Database Error Disclosure": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"},
	"Blind SQL Injection Test":  {9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"},

	// Port Scanner
	"Open Port Detection": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "High"},

	// Open Redirect
	"Open Redirect Test": {6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"},

	// SSRF
	"SSRF Detection": {9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Critical"},

	// Email Security
	"Email Security Score": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Medium"},

	// WAF
	"WAF Detection": {5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Medium"},

	// DNS Zone Transfer
	"DNS Zone Transfer": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},

	// Data Leak
	"Domain Breach History": {9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Critical"},
	"Email Breach Detection": {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},
	"Paste Site Exposure":    {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"},
}

// GetCVSSMapping returns the CVSS mapping for a given check name, or nil if not mapped
func GetCVSSMapping(checkName string) *CVSSMapping {
	if m, ok := CheckCVSSMap[checkName]; ok {
		return &m
	}
	return nil
}
