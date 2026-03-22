package api

import "github.com/gofiber/fiber/v2"

// GetScanCriteria returns the complete VScan-MOHESR scoring methodology as JSON.
// This is a PUBLIC endpoint – no authentication required.
func GetScanCriteria(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"methodology": fiber.Map{
			"name":        "VScan-MOHESR Security Assessment Methodology",
			"version":     "2.0",
			"max_score":   1000,
			"description": "Comprehensive website security assessment framework developed for the Iraqi Ministry of Higher Education and Scientific Research (MOHESR). This methodology evaluates 12 security categories across 40+ individual checks to produce a normalized score on a 1000-point scale. Each category carries a percentage weight that reflects its relative importance to the overall security posture of a website.",

			"scoring_formula": "Overall Score = SUM(check_score * check_weight) / SUM(check_weight), where each check_score is on a 0-1000 scale.",

			"categories": []fiber.Map{
				// ---------------------------------------------------------------
				// 1. SSL/TLS (Weight: 20%)
				// ---------------------------------------------------------------
				{
					"id":          "ssl",
					"name":        "SSL/TLS Encryption",
					"weight":      20.0,
					"max_score":   1000,
					"description": "Evaluates the quality and configuration of the website's TLS/SSL encryption, including certificate validity, protocol versions, and HTTPS enforcement.",
					"importance":  "critical",
					"checks": []fiber.Map{
						{
							"name":        "HTTPS Enabled",
							"weight":      50,
							"max_score":   1000,
							"description": "Verifies the website is accessible over encrypted HTTPS connection.",
							"scoring": []fiber.Map{
								{"condition": "HTTPS available with fast response (<5s)", "score": 1000},
								{"condition": "HTTPS available but slow response (>5s)", "score": 800},
								{"condition": "HTTPS not available", "score": 0},
							},
						},
						{
							"name":        "Certificate Validity",
							"weight":      50,
							"max_score":   1000,
							"description": "Checks the TLS certificate for expiration, validity period, issuer trust, and whether it is self-signed.",
							"scoring": []fiber.Map{
								{"condition": "Valid certificate, >90 days until expiry", "score": 1000},
								{"condition": "Valid certificate, 60-90 days until expiry", "score": 900},
								{"condition": "Valid certificate, 30-60 days until expiry", "score": 750},
								{"condition": "Valid certificate, 14-30 days until expiry", "score": 500},
								{"condition": "Valid certificate, 7-14 days until expiry", "score": 300},
								{"condition": "Valid certificate, <7 days until expiry", "score": 150},
								{"condition": "Self-signed certificate", "score": 400},
								{"condition": "Expired or not yet valid certificate", "score": 0},
								{"condition": "No certificate / TLS connection failed", "score": 0},
							},
						},
						{
							"name":        "TLS Version",
							"weight":      50,
							"max_score":   1000,
							"description": "Checks the negotiated TLS protocol version and cipher suite strength.",
							"scoring": []fiber.Map{
								{"condition": "TLS 1.3", "score": 1000},
								{"condition": "TLS 1.2 with strong AEAD cipher suite (AES-GCM, ChaCha20)", "score": 850},
								{"condition": "TLS 1.2 with weaker cipher suite", "score": 700},
								{"condition": "TLS 1.1 (deprecated)", "score": 200},
								{"condition": "TLS 1.0 or older", "score": 0},
							},
						},
						{
							"name":        "HTTP to HTTPS Redirect",
							"weight":      50,
							"max_score":   1000,
							"description": "Verifies that HTTP requests are properly redirected to HTTPS.",
							"scoring": []fiber.Map{
								{"condition": "301 permanent redirect to HTTPS", "score": 1000},
								{"condition": "302 temporary redirect to HTTPS", "score": 850},
								{"condition": "Other 3xx redirect to HTTPS", "score": 700},
								{"condition": "No redirect but HTTPS available separately", "score": 400},
								{"condition": "HTTP not reachable, HTTPS works directly", "score": 400},
								{"condition": "Neither HTTP nor HTTPS reachable", "score": 0},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 2. Security Headers (Weight: 20%)
				// ---------------------------------------------------------------
				{
					"id":          "headers",
					"name":        "Security Headers",
					"weight":      20.0,
					"max_score":   1000,
					"description": "Evaluates the presence and configuration of HTTP security response headers that protect against common web attacks.",
					"importance":  "critical",
					"checks": []fiber.Map{
						{
							"name":        "HSTS (Strict-Transport-Security)",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Enforces HTTPS connections, preventing protocol downgrade attacks and cookie hijacking.",
							"scoring": []fiber.Map{
								{"condition": "max-age >= 1 year + includeSubDomains + preload", "score": 1000},
								{"condition": "max-age >= 1 year + includeSubDomains (no preload)", "score": 920},
								{"condition": "max-age >= 1 year (no includeSubDomains)", "score": 800},
								{"condition": "max-age >= 6 months but < 1 year", "score": 650},
								{"condition": "max-age < 6 months", "score": 400},
								{"condition": "max-age = 0 (effectively disabled)", "score": 100},
								{"condition": "Header missing", "score": 0},
							},
						},
						{
							"name":        "Content Security Policy (CSP)",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Prevents XSS and data injection attacks by controlling which resources the browser is allowed to load.",
							"scoring": []fiber.Map{
								{"condition": "CSP present with specific sources, no unsafe directives", "score": 1000},
								{"condition": "CSP present with 'unsafe-inline' but no 'unsafe-eval'", "score": 700},
								{"condition": "CSP present with both 'unsafe-inline' and 'unsafe-eval'", "score": 400},
								{"condition": "CSP present but too permissive (default-src *)", "score": 200},
								{"condition": "Header missing", "score": 0},
							},
						},
						{
							"name":        "X-Frame-Options",
							"weight":      3.0,
							"max_score":   1000,
							"description": "Prevents clickjacking attacks by controlling whether the page can be embedded in iframes.",
							"scoring": []fiber.Map{
								{"condition": "Set to DENY", "score": 1000},
								{"condition": "Set to SAMEORIGIN", "score": 900},
								{"condition": "Set to ALLOW-FROM specific origin", "score": 700},
								{"condition": "Present but unrecognized value", "score": 400},
								{"condition": "Header missing", "score": 0},
							},
						},
						{
							"name":        "X-Content-Type-Options",
							"weight":      3.0,
							"max_score":   1000,
							"description": "Prevents MIME type sniffing, which can lead to security vulnerabilities when browsers interpret files as different content types.",
							"scoring": []fiber.Map{
								{"condition": "Set to nosniff", "score": 1000},
								{"condition": "Present but not set to nosniff", "score": 400},
								{"condition": "Header missing", "score": 0},
							},
						},
						{
							"name":        "X-XSS-Protection",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Legacy XSS filter for older browsers. Modern browsers rely on CSP, but this header still provides defense-in-depth.",
							"scoring": []fiber.Map{
								{"condition": "1; mode=block", "score": 1000},
								{"condition": "1 (enabled without mode=block)", "score": 700},
								{"condition": "0 (intentionally disabled, acceptable when CSP present)", "score": 500},
								{"condition": "Present but unrecognized value", "score": 300},
								{"condition": "Header missing", "score": 0},
							},
						},
						{
							"name":        "Referrer-Policy",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Controls how much referrer information is included with requests, protecting user privacy and preventing data leakage.",
							"scoring": []fiber.Map{
								{"condition": "no-referrer or same-origin", "score": 1000},
								{"condition": "strict-origin-when-cross-origin", "score": 900},
								{"condition": "strict-origin", "score": 850},
								{"condition": "origin-when-cross-origin", "score": 600},
								{"condition": "origin", "score": 500},
								{"condition": "no-referrer-when-downgrade", "score": 400},
								{"condition": "unsafe-url", "score": 100},
								{"condition": "Header missing", "score": 0},
							},
						},
						{
							"name":        "Permissions-Policy",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Controls which browser features (camera, microphone, geolocation, etc.) can be used by the page and its embedded content.",
							"scoring": []fiber.Map{
								{"condition": "Present with restrictive settings", "score": 1000},
								{"condition": "Present but permissive (wildcard or no restrictions)", "score": 500},
								{"condition": "Header missing", "score": 0},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 3. Cookie Security (Weight: 10%)
				// ---------------------------------------------------------------
				{
					"id":          "cookies",
					"name":        "Cookie Security",
					"weight":      10.0,
					"max_score":   1000,
					"description": "Evaluates the security attributes of cookies set by the website, including encryption, script access prevention, and cross-site request protection.",
					"importance":  "high",
					"checks": []fiber.Map{
						{
							"name":        "Cookie Security Attributes",
							"weight":      10.0,
							"max_score":   1000,
							"description": "Each cookie is evaluated for Secure, HttpOnly, and SameSite attributes. Weight is distributed equally across all cookies found. If no cookies are set, a perfect score is awarded.",
							"scoring": []fiber.Map{
								{"condition": "No cookies set on initial response", "score": 1000},
								{"condition": "All three attributes present (Secure + HttpOnly + SameSite)", "score": 1000},
								{"condition": "Missing Secure flag", "score": "-350 penalty per cookie"},
								{"condition": "Missing HttpOnly flag", "score": "-325 penalty per cookie"},
								{"condition": "Missing SameSite attribute", "score": "-325 penalty per cookie"},
								{"condition": "All three attributes missing", "score": 0},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 4. Server Information (Weight: 15%)
				// ---------------------------------------------------------------
				{
					"id":          "server_info",
					"name":        "Server Information Exposure",
					"weight":      15.0,
					"max_score":   1000,
					"description": "Checks whether the server exposes software identity, technology stack, or CMS information that could aid attackers in targeting known vulnerabilities.",
					"importance":  "high",
					"checks": []fiber.Map{
						{
							"name":        "Server Header Exposure",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Checks if the Server HTTP header reveals web server software and version.",
							"scoring": []fiber.Map{
								{"condition": "Server header not exposed", "score": 1000},
								{"condition": "Server header exposes software information", "score": 400},
							},
						},
						{
							"name":        "X-Powered-By Exposure",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Checks if the X-Powered-By header reveals the application framework or runtime.",
							"scoring": []fiber.Map{
								{"condition": "X-Powered-By header not exposed", "score": 1000},
								{"condition": "X-Powered-By header exposes technology stack", "score": 200},
							},
						},
						{
							"name":        "CMS Detection",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Attempts to detect the Content Management System (WordPress, Joomla, Drupal, Moodle) by probing known paths and response headers.",
							"scoring": []fiber.Map{
								{"condition": "No common CMS detected", "score": 1000},
								{"condition": "CMS detected (WordPress, Joomla, Drupal, Moodle)", "score": 700},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 5. Sensitive Directory / File Exposure (Weight: 10%)
				// ---------------------------------------------------------------
				{
					"id":          "directory",
					"name":        "Sensitive Directory & File Exposure",
					"weight":      10.0,
					"max_score":   1000,
					"description": "Probes for common sensitive paths and files that should not be publicly accessible, such as environment files, version control directories, backup files, and admin panels.",
					"importance":  "high",
					"checks": []fiber.Map{
						{
							"name":        "robots.txt Exposure",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if robots.txt is present and whether it discloses sensitive paths.",
							"scoring": []fiber.Map{
								{"condition": "robots.txt found (informational)", "score": 900},
								{"condition": "Path not accessible or not found", "score": 1000},
							},
						},
						{
							"name":        "Environment File Exposure (.env)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if .env file containing secrets is publicly accessible.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "File accessible with content", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "Git Repository Exposure (.git/config)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if the .git directory is publicly accessible, which can expose source code.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "File accessible with content", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "PHP Info Exposure (phpinfo.php)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if phpinfo.php is accessible, which reveals detailed server configuration.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "File accessible", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "Admin Panel Exposure (/admin/)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if a default admin panel path is publicly accessible.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "Admin panel accessible", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "Backup Directory Exposure (/backup/)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if backup directories are publicly accessible.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "Directory accessible", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "Htaccess File Exposure (.htaccess)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if .htaccess configuration file is publicly readable.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "File accessible", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "WordPress Config Backup (wp-config.php.bak)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if WordPress configuration backup file is publicly accessible.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "File accessible", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
						{
							"name":        "Server Status Exposure (/server-status)",
							"weight":      1.11,
							"max_score":   1000,
							"description": "Checks if Apache server-status page is publicly accessible.",
							"scoring": []fiber.Map{
								{"condition": "Path not found (404/other)", "score": 1000},
								{"condition": "Path exists but forbidden (403)", "score": 700},
								{"condition": "Page accessible", "score": 100},
								{"condition": "Directory listing enabled", "score": 0},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 6. Performance (Weight: 15%)
				// ---------------------------------------------------------------
				{
					"id":          "performance",
					"name":        "Performance & Response Time",
					"weight":      15.0,
					"max_score":   1000,
					"description": "Measures server performance metrics that impact both user experience and security. Slow servers are more susceptible to denial-of-service attacks.",
					"importance":  "high",
					"checks": []fiber.Map{
						{
							"name":        "Response Time",
							"weight":      50.0,
							"max_score":   1000,
							"description": "Measures total HTTP response time including DNS, connection, TLS handshake, and content transfer.",
							"scoring": []fiber.Map{
								{"condition": "<= 200ms", "score": 1000},
								{"condition": "200-500ms (linear decay)", "score": "1000-900"},
								{"condition": "500ms-1s (linear decay)", "score": "900-750"},
								{"condition": "1-2s (linear decay)", "score": "750-500"},
								{"condition": "2-5s (linear decay)", "score": "500-200"},
								{"condition": "5-10s (linear decay)", "score": "200-50"},
								{"condition": "> 10s", "score": 0},
							},
						},
						{
							"name":        "Time to First Byte (TTFB)",
							"weight":      50.0,
							"max_score":   1000,
							"description": "Measures the time until the first byte of the response is received, indicating server processing speed.",
							"scoring": []fiber.Map{
								{"condition": "<= 100ms", "score": 1000},
								{"condition": "100-200ms (linear decay)", "score": "1000-920"},
								{"condition": "200-500ms (linear decay)", "score": "920-750"},
								{"condition": "500ms-1s (linear decay)", "score": "750-450"},
								{"condition": "1-2s (linear decay)", "score": "450-200"},
								{"condition": "2-5s (linear decay)", "score": "200-50"},
								{"condition": "> 5s", "score": 0},
							},
						},
						{
							"name":        "TLS Handshake Time",
							"weight":      50.0,
							"max_score":   1000,
							"description": "Measures the TLS handshake duration, which impacts initial connection speed and user experience.",
							"scoring": []fiber.Map{
								{"condition": "<= 50ms", "score": 1000},
								{"condition": "50-100ms (linear decay)", "score": "1000-920"},
								{"condition": "100-300ms (linear decay)", "score": "920-750"},
								{"condition": "300-700ms (linear decay)", "score": "750-450"},
								{"condition": "700-1500ms (linear decay)", "score": "450-150"},
								{"condition": "> 1500ms", "score": 50},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 7. DDoS Protection (Weight: 10%)
				// ---------------------------------------------------------------
				{
					"id":          "ddos",
					"name":        "DDoS & Infrastructure Protection",
					"weight":      10.0,
					"max_score":   1000,
					"description": "Evaluates the presence of CDN, DDoS protection services, rate limiting, and Web Application Firewalls that protect the website from volumetric and application-layer attacks.",
					"importance":  "high",
					"checks": []fiber.Map{
						{
							"name":        "CDN/DDoS Protection Service",
							"weight":      4.0,
							"max_score":   1000,
							"description": "Detects CDN and DDoS protection services (Cloudflare, AWS CloudFront, Akamai, Fastly, Sucuri, Imperva, Azure Front Door, Google Cloud CDN) by inspecting response headers.",
							"scoring": []fiber.Map{
								{"condition": "Protection service detected", "score": 1000},
								{"condition": "No CDN or DDoS protection detected", "score": 0},
							},
						},
						{
							"name":        "Rate Limiting",
							"weight":      3.0,
							"max_score":   1000,
							"description": "Checks for rate limiting headers (X-RateLimit-*, RateLimit-*, Retry-After) that indicate API/request throttling is in place.",
							"scoring": []fiber.Map{
								{"condition": "Rate limiting headers detected", "score": 1000},
								{"condition": "No rate limiting headers detected", "score": 300},
							},
						},
						{
							"name":        "Web Application Firewall (WAF)",
							"weight":      3.0,
							"max_score":   1000,
							"description": "Detects WAF presence by inspecting headers and testing with a simulated XSS payload to see if the request is blocked or filtered.",
							"scoring": []fiber.Map{
								{"condition": "WAF detected (ModSecurity, Cloudflare, Imperva, Sucuri, or block response)", "score": 1000},
								{"condition": "No WAF detected", "score": 100},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 8. CORS Configuration (Weight: 10%)
				// ---------------------------------------------------------------
				{
					"id":          "cors",
					"name":        "CORS Configuration",
					"weight":      10.0,
					"max_score":   1000,
					"description": "Evaluates Cross-Origin Resource Sharing (CORS) configuration to ensure the website does not inadvertently expose data to unauthorized domains.",
					"importance":  "high",
					"checks": []fiber.Map{
						{
							"name":        "CORS Wildcard Origin",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Sends a cross-origin request with a malicious Origin header to check if the server reflects arbitrary origins or uses wildcard (*).",
							"scoring": []fiber.Map{
								{"condition": "No CORS header exposed to foreign origins", "score": 1000},
								{"condition": "CORS configured with specific allowed origin", "score": 900},
								{"condition": "CORS not checkable", "score": 800},
								{"condition": "CORS allows all origins (*)", "score": 400},
								{"condition": "CORS reflects arbitrary origins", "score": 0},
							},
						},
						{
							"name":        "CORS Credentials",
							"weight":      5.0,
							"max_score":   1000,
							"description": "Checks if CORS allows credentials (cookies, auth headers) along with permissive origin settings, which is a critical vulnerability.",
							"scoring": []fiber.Map{
								{"condition": "Credentials not allowed or CORS properly restricted", "score": 1000},
								{"condition": "CORS not checkable", "score": 800},
								{"condition": "Credentials allowed with specific origin", "score": 600},
								{"condition": "Credentials allowed with wildcard/reflected origin", "score": 0},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 9. HTTP Methods (Weight: 8%)
				// ---------------------------------------------------------------
				{
					"id":          "http_methods",
					"name":        "HTTP Methods Security",
					"weight":      8.0,
					"max_score":   1000,
					"description": "Checks whether dangerous HTTP methods (TRACE, DELETE, PUT, PATCH) are properly restricted and whether the OPTIONS response discloses sensitive information.",
					"importance":  "medium",
					"checks": []fiber.Map{
						{
							"name":        "Dangerous HTTP Methods",
							"weight":      4.0,
							"max_score":   1000,
							"description": "Tests TRACE, DELETE, PUT, and PATCH methods. These should return 405, 501, or 403 on public endpoints.",
							"scoring": []fiber.Map{
								{"condition": "All dangerous methods properly disabled (405/501/403)", "score": 1000},
								{"condition": "One or more dangerous methods are enabled", "score": 200},
							},
						},
						{
							"name":        "OPTIONS Method Disclosure",
							"weight":      4.0,
							"max_score":   1000,
							"description": "Checks the OPTIONS response for the Allow header to see if dangerous methods are advertised.",
							"scoring": []fiber.Map{
								{"condition": "OPTIONS properly configured or not accessible", "score": 1000},
								{"condition": "OPTIONS discloses dangerous methods (TRACE, DELETE)", "score": 400},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 10. DNS Security (Weight: 8%)
				// ---------------------------------------------------------------
				{
					"id":          "dns",
					"name":        "DNS Security",
					"weight":      8.0,
					"max_score":   1000,
					"description": "Evaluates DNS security records that protect against domain spoofing, email phishing, and unauthorized certificate issuance.",
					"importance":  "medium",
					"checks": []fiber.Map{
						{
							"name":        "DNSSEC",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Checks for DNSSEC (Domain Name System Security Extensions) which protects against DNS spoofing and cache poisoning.",
							"scoring": []fiber.Map{
								{"condition": "DNS resolves successfully (partial verification)", "score": 700},
								{"condition": "Domain cannot be resolved", "score": 0},
							},
						},
						{
							"name":        "SPF Record (Email Security)",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Checks for Sender Policy Framework (SPF) DNS record that specifies which mail servers are authorized to send email on behalf of the domain.",
							"scoring": []fiber.Map{
								{"condition": "SPF with strict policy (-all)", "score": 1000},
								{"condition": "SPF with soft fail (~all)", "score": 700},
								{"condition": "SPF present with permissive policy", "score": 500},
								{"condition": "Cannot lookup TXT records", "score": 300},
								{"condition": "No SPF record found", "score": 0},
							},
						},
						{
							"name":        "DMARC Record (Email Security)",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Checks for Domain-based Message Authentication, Reporting, and Conformance (DMARC) record that tells receivers what to do with emails that fail SPF/DKIM checks.",
							"scoring": []fiber.Map{
								{"condition": "DMARC with p=reject", "score": 1000},
								{"condition": "DMARC with p=quarantine", "score": 800},
								{"condition": "DMARC with p=none (monitor only)", "score": 400},
								{"condition": "No DMARC record found", "score": 0},
							},
						},
						{
							"name":        "CAA Record (Certificate Authority)",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Checks for Certificate Authority Authorization (CAA) records that restrict which CAs can issue certificates for the domain.",
							"scoring": []fiber.Map{
								{"condition": "DNS properly configured (CAA recommended)", "score": 700},
								{"condition": "Cannot verify CAA records", "score": 600},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 11. Mixed Content (Weight: 7%)
				// ---------------------------------------------------------------
				{
					"id":          "mixed_content",
					"name":        "Mixed Content",
					"weight":      7.0,
					"max_score":   1000,
					"description": "Checks the HTTPS page source for HTTP (insecure) resources. Mixed content undermines the security benefits of HTTPS and may be blocked by modern browsers.",
					"importance":  "medium",
					"checks": []fiber.Map{
						{
							"name":        "Mixed Active Content (Scripts/CSS)",
							"weight":      3.0,
							"max_score":   1000,
							"description": "Scans for HTTP-loaded scripts (.js) and stylesheets (.css) on the HTTPS page. Active mixed content is the most dangerous as it can modify the DOM.",
							"scoring": []fiber.Map{
								{"condition": "No mixed active content detected", "score": 1000},
								{"condition": "HTTP scripts or CSS found on HTTPS page", "score": 0},
							},
						},
						{
							"name":        "Mixed Passive Content (Images/Media)",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Scans for HTTP-loaded images and media files (jpg, png, gif, svg, webp, mp4, mp3) on the HTTPS page.",
							"scoring": []fiber.Map{
								{"condition": "No mixed passive content detected", "score": 1000},
								{"condition": "HTTP images or media found on HTTPS page", "score": 400},
							},
						},
						{
							"name":        "Insecure Form Actions",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Checks if any forms submit data to HTTP URLs, which would transmit user input (including passwords) in plaintext.",
							"scoring": []fiber.Map{
								{"condition": "No insecure form actions detected", "score": 1000},
								{"condition": "Forms submit over HTTP (no password fields)", "score": 100},
								{"condition": "Forms with password fields submit over HTTP", "score": 0},
							},
						},
					},
				},

				// ---------------------------------------------------------------
				// 12. Information Disclosure (Weight: 7%)
				// ---------------------------------------------------------------
				{
					"id":          "info_disclosure",
					"name":        "Information Disclosure",
					"weight":      7.0,
					"max_score":   1000,
					"description": "Checks for unintentional disclosure of sensitive information through error pages, HTML comments, and technology version exposure.",
					"importance":  "medium",
					"checks": []fiber.Map{
						{
							"name":        "Error Page Information Disclosure",
							"weight":      3.0,
							"max_score":   1000,
							"description": "Requests a non-existent page and inspects the error response for stack traces, server versions, framework names, file paths, SQL errors, and debug mode indicators.",
							"scoring": []fiber.Map{
								{"condition": "Error pages do not reveal sensitive information", "score": 1000},
								{"condition": "Cannot check error pages", "score": 800},
								{"condition": "Error page reveals sensitive information (paths, versions, stack traces)", "score": 100},
							},
						},
						{
							"name":        "Sensitive HTML Comments",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Scans HTML source for comments containing sensitive keywords: password, todo, fixme, hack, bug, secret, api_key, token, admin, debug, database.",
							"scoring": []fiber.Map{
								{"condition": "No sensitive keywords in HTML comments", "score": 1000},
								{"condition": "HTML comments contain sensitive keywords", "score": 400},
							},
						},
						{
							"name":        "Technology Version Disclosure",
							"weight":      2.0,
							"max_score":   1000,
							"description": "Checks for version information in meta generator tags, WordPress signatures, jQuery versions, and X-Powered-By/X-AspNet-Version headers.",
							"scoring": []fiber.Map{
								{"condition": "No significant technology version disclosures", "score": 1000},
								{"condition": "Technology versions are exposed", "score": 400},
							},
						},
					},
				},
			},

			"grading_scale": []fiber.Map{
				{"grade": "A+", "min_score": 900, "max_score": 1000, "label": "Excellent", "description": "Outstanding security posture with best-practice configurations across all categories."},
				{"grade": "A", "min_score": 800, "max_score": 899, "label": "Very Good", "description": "Strong security with minor improvements possible."},
				{"grade": "B", "min_score": 700, "max_score": 799, "label": "Good", "description": "Solid security foundation with some areas needing attention."},
				{"grade": "C", "min_score": 600, "max_score": 699, "label": "Average", "description": "Moderate security level; several improvements recommended."},
				{"grade": "D", "min_score": 500, "max_score": 599, "label": "Below Average", "description": "Significant security gaps that should be addressed promptly."},
				{"grade": "F", "min_score": 0, "max_score": 499, "label": "Failing", "description": "Critical security deficiencies requiring immediate remediation."},
			},
		},
	})
}
