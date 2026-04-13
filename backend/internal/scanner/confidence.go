package scanner

// ConfidenceLevel defines how confident we are in a check result
// 100 = deterministic (exact version match, header present/absent)
// 80  = high confidence (pattern matching, heuristic detection)
// 60  = medium confidence (indirect indicators)
// 40  = low confidence (speculation, missing data interpreted as negative)

var CheckConfidence = map[string]int{
	// SSL - deterministic checks
	"HTTPS Enabled":          100,
	"Certificate Validity":   100,
	"TLS Version":            100,
	"HTTP to HTTPS Redirect": 100,

	// Headers - deterministic (header is present or not)
	"HSTS":                    100,
	"Content Security Policy": 100,
	"X-Frame-Options":         100,
	"X-Content-Type-Options":  100,
	"X-XSS-Protection":        100,
	"Referrer-Policy":         100,
	"Permissions-Policy":      100,

	// Cookies - deterministic
	"Cookie Security": 100,

	// Server Info - high confidence
	"Server Header Exposure": 95,
	"X-Powered-By Exposure":  100,
	"CMS Detection":          70, // heuristic pattern matching

	// Directory - varies (403 vs 404 interpretation)
	"Environment File Exposure": 85,
	"Git Repository Exposure":   85,
	"PHP Info Exposure":         90,
	"Admin Panel Exposure":      80,
	"Backup Directory Exposure": 85,
	"Htaccess File Exposure":    85,
	"WordPress Config Backup":   85,
	"Server Status Exposure":    90,
	"Robots.txt Exposure":       100,

	// Performance - varies by network conditions
	"Response Time":             60, // network dependent
	"Time to First Byte (TTFB)": 60,
	"TLS Handshake Time":        60,

	// DDoS - heuristic
	"CDN/DDoS Protection Service":    85,
	"Rate Limiting":                  70, // headers may not be present but rate limiting exists
	"Web Application Firewall (WAF)": 75,

	// CORS - deterministic
	"CORS Wildcard Origin": 100,
	"CORS Credentials":     100,

	// HTTP Methods - deterministic
	"Dangerous HTTP Methods":    95,
	"OPTIONS Method Disclosure": 100,

	// DNS - deterministic
	"SPF Record (Email Security)":        100,
	"DMARC Record (Email Security)":      100,
	"CAA Record (Certificate Authority)": 90,

	// Mixed Content - high confidence
	"Mixed Active Content (Scripts/CSS)":  90,
	"Mixed Passive Content (Images/Media)": 90,
	"Insecure Form Actions":               95,

	// Info Disclosure - varies
	"Error Page Information Disclosure": 80,
	"Sensitive HTML Comments":           85,
	"Technology Version Disclosure":     75,

	// Hosting - deterministic
	"HTTP/2 Support":        100,
	"HTTP/3 (QUIC) Support": 95,
	"Brotli Compression":    100,
	"IPv6 Support":          100,
	"Keep-Alive":            95,
	"DNS Resolution Time":   60,

	// Content - high confidence
	"Cache Headers":     100,
	"Page Size":         100,
	"Compression Ratio": 85,

	// Advanced Security - deterministic
	"Cross-Origin-Embedder-Policy (COEP)": 100,
	"Cross-Origin-Opener-Policy (COOP)":   100,
	"Cross-Origin-Resource-Policy (CORP)":  100,
	"OCSP Stapling":                        90,

	// Malware - varies
	"Malicious JavaScript Detection": 75,
	"Hidden Iframe Detection":        80,
	"Cryptocurrency Miner Detection": 90,
	"Suspicious Redirect Detection":  70,
	"Malware Signature Detection":    65,
	"Malicious External Links":       60,

	// SEO - deterministic
	"Meta Tags Quality":     100,
	"Open Graph Tags":       100,
	"Sitemap Accessibility": 100,
	"Robots.txt Quality":    100,
	"Structured Data":       95,
	"Mobile Friendliness":   85,

	// Third Party - high confidence
	"External Script Count":       100,
	"Subresource Integrity (SRI)": 100,
	"Trusted Sources":             80,
	"External CSS Count":          100,

	// JS Libraries - varies
	"Outdated jQuery Detection":  85,
	"Known Vulnerable Libraries": 75,
	"Inline Script Analysis":     70,

	// XSS Vulnerability Scanner - varies (canary-based heuristic)
	"Reflected XSS Detection":                80,
	"DOM-Based XSS Indicators":               70,
	"Input Sanitization Check":               75,
	"Content-Type & X-XSS-Protection Headers": 100,
	"URL Parameter Reflection Analysis":       75,

	// Secrets Detection Scanner
	"API Key Exposure":                    90,
	"Private Key Exposure":                95,
	"Database Connection String Exposure": 85,
	"Email/Password Exposure":             80,

	// Subdomain Discovery Scanner
	"Common Subdomain Enumeration":          70,
	"Subdomain Security Check":              90,
	"Dangling DNS / Subdomain Takeover Risk": 75,

	// Technology Detection Scanner
	"Web Framework Detection":      85,
	"Server Technology Detection":  85,
	"JavaScript Library Inventory": 85,

	// SQL Injection Scanner
	"SQL Injection Test":        70, // error-based detection, may have false positives
	"Database Error Disclosure": 85,
	"Blind SQL Injection Test":  60, // time-based, network-dependent

	// Port Scanner
	"Open Port Detection": 95, // deterministic TCP connection

	// Open Redirect
	"Open Redirect Test": 75,

	// SSRF
	"SSRF Detection": 65, // heuristic-based

	// Email Security
	"DKIM Record":         100, // DNS lookup, deterministic
	"BIMI Record":         100,
	"Email Security Score": 95,

	// WAF Fingerprinting
	"WAF Detection": 80,

	// DNS Zone Transfer
	"DNS Zone Transfer": 100, // deterministic

	// Data Leak Scanner
	"Domain Breach History": 90,  // based on HIBP public data
	"Email Breach Detection": 85, // depends on API availability
	"Paste Site Exposure":    80,  // depends on API availability
}

func GetConfidence(checkName string) int {
	if conf, ok := CheckConfidence[checkName]; ok {
		return conf
	}
	return 80 // default
}
