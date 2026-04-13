package scanner

// OWASPMapping maps check names to OWASP Top 10 2021 and CWE IDs
type OWASPMapping struct {
	OWASP     string `json:"owasp"`      // e.g., "A02:2021"
	OWASPName string `json:"owasp_name"` // e.g., "Cryptographic Failures"
	CWE       string `json:"cwe"`        // e.g., "CWE-295"
	CWEName   string `json:"cwe_name"`   // e.g., "Improper Certificate Validation"
	CVSSBase  string `json:"cvss_base"`  // e.g., "Medium" or "High"
}

// CheckOWASPMap provides OWASP Top 10 2021 and CWE mappings for every scanner check.
var CheckOWASPMap = map[string]OWASPMapping{

	// =========================================================================
	// SSL/TLS Scanner
	// =========================================================================
	"HTTPS Enabled": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information",
		CVSSBase: "High",
	},
	"Certificate Validity": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-295", CWEName: "Improper Certificate Validation",
		CVSSBase: "High",
	},
	"TLS Version": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-326", CWEName: "Inadequate Encryption Strength",
		CVSSBase: "Medium",
	},
	"HTTP to HTTPS Redirect": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information",
		CVSSBase: "Medium",
	},

	// =========================================================================
	// Security Headers Scanner
	// =========================================================================
	"HSTS": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-523", CWEName: "Unprotected Transport of Credentials",
		CVSSBase: "Medium",
	},
	"Content Security Policy": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "High",
	},
	"X-Frame-Options": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-1021", CWEName: "Improper Restriction of Rendered UI Layers or Frames (Clickjacking)",
		CVSSBase: "Medium",
	},
	"X-Content-Type-Options": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Low",
	},
	"X-XSS-Protection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "Medium",
	},
	"Referrer-Policy": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Low",
	},
	"Permissions-Policy": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-250", CWEName: "Execution with Unnecessary Privileges",
		CVSSBase: "Low",
	},

	// =========================================================================
	// Cookie Scanner
	// =========================================================================
	"Cookie Security": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-614", CWEName: "Sensitive Cookie in HTTPS Session Without Secure Attribute",
		CVSSBase: "Medium",
	},

	// =========================================================================
	// Server Info Scanner
	// =========================================================================
	"Server Header Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Low",
	},
	"X-Powered-By Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Low",
	},
	"CMS Detection": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Low",
	},

	// =========================================================================
	// Directory Scanner
	// =========================================================================
	"Robots.txt Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "Informational",
	},
	"Environment File Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "Critical",
	},
	"Git Repository Exposure": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "Critical",
	},
	"PHP Info Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "High",
	},
	"Admin Panel Exposure": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-425", CWEName: "Direct Request (Forced Browsing)",
		CVSSBase: "High",
	},
	"Backup Directory Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "Critical",
	},
	"Htaccess File Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "High",
	},
	"WordPress Config Backup": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "Critical",
	},
	"Server Status Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-538", CWEName: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
		CVSSBase: "High",
	},

	// =========================================================================
	// Performance Scanner
	// =========================================================================
	"Response Time": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-400", CWEName: "Uncontrolled Resource Consumption",
		CVSSBase: "Informational",
	},
	"Time to First Byte (TTFB)": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-400", CWEName: "Uncontrolled Resource Consumption",
		CVSSBase: "Informational",
	},
	"TLS Handshake Time": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-400", CWEName: "Uncontrolled Resource Consumption",
		CVSSBase: "Informational",
	},

	// =========================================================================
	// DDoS Scanner
	// =========================================================================
	"CDN/DDoS Protection Service": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-770", CWEName: "Allocation of Resources Without Limits or Throttling",
		CVSSBase: "High",
	},
	"Rate Limiting": {
		OWASP: "A04:2021", OWASPName: "Insecure Design",
		CWE: "CWE-770", CWEName: "Allocation of Resources Without Limits or Throttling",
		CVSSBase: "Medium",
	},
	"Web Application Firewall (WAF)": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-693", CWEName: "Protection Mechanism Failure",
		CVSSBase: "High",
	},

	// =========================================================================
	// CORS Scanner
	// =========================================================================
	"CORS Wildcard Origin": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-942", CWEName: "Permissive Cross-domain Policy with Untrusted Domains",
		CVSSBase: "High",
	},
	"CORS Credentials": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-942", CWEName: "Permissive Cross-domain Policy with Untrusted Domains",
		CVSSBase: "High",
	},

	// =========================================================================
	// HTTP Methods Scanner
	// =========================================================================
	"Dangerous HTTP Methods": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-749", CWEName: "Exposed Dangerous Method or Function",
		CVSSBase: "Medium",
	},
	"OPTIONS Method Disclosure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-749", CWEName: "Exposed Dangerous Method or Function",
		CVSSBase: "Low",
	},

	// =========================================================================
	// DNS Scanner
	// =========================================================================
	"SPF Record (Email Security)": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-290", CWEName: "Authentication Bypass by Spoofing",
		CVSSBase: "Medium",
	},
	"DMARC Record (Email Security)": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-290", CWEName: "Authentication Bypass by Spoofing",
		CVSSBase: "Medium",
	},
	"CAA Record (Certificate Authority)": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-295", CWEName: "Improper Certificate Validation",
		CVSSBase: "Low",
	},

	// =========================================================================
	// Mixed Content Scanner
	// =========================================================================
	"Mixed Active Content (Scripts/CSS)": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information",
		CVSSBase: "High",
	},
	"Mixed Passive Content (Images/Media)": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information",
		CVSSBase: "Medium",
	},
	"Insecure Form Actions": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information",
		CVSSBase: "High",
	},
	"Mixed Content": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information",
		CVSSBase: "Medium",
	},

	// =========================================================================
	// Information Disclosure Scanner
	// =========================================================================
	"Error Page Information Disclosure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-209", CWEName: "Generation of Error Message Containing Sensitive Information",
		CVSSBase: "Medium",
	},
	"Sensitive HTML Comments": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-615", CWEName: "Inclusion of Sensitive Information in Source Code Comments",
		CVSSBase: "Low",
	},
	"Technology Version Disclosure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Low",
	},

	// =========================================================================
	// Hosting Quality Scanner
	// =========================================================================
	"HTTP/2 Support": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"HTTP/3 (QUIC) Support": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"Brotli Compression": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"IPv6 Support": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"Keep-Alive": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"DNS Resolution Time": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},

	// =========================================================================
	// Content Optimization Scanner
	// =========================================================================
	"Cache Headers": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"Page Size": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"Compression Ratio": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},

	// =========================================================================
	// Advanced Security Scanner
	// =========================================================================
	"Cross-Origin-Embedder-Policy": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-346", CWEName: "Origin Validation Error",
		CVSSBase: "Medium",
	},
	"Cross-Origin-Opener-Policy": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-346", CWEName: "Origin Validation Error",
		CVSSBase: "Medium",
	},
	"Cross-Origin-Resource-Policy": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-346", CWEName: "Origin Validation Error",
		CVSSBase: "Medium",
	},
	"OCSP Stapling": {
		OWASP: "A02:2021", OWASPName: "Cryptographic Failures",
		CWE: "CWE-299", CWEName: "Improper Check for Certificate Revocation",
		CVSSBase: "Low",
	},

	// =========================================================================
	// Malware Scanner
	// =========================================================================
	"Malicious JavaScript Detection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-94", CWEName: "Improper Control of Generation of Code (Code Injection)",
		CVSSBase: "Critical",
	},
	"Hidden Iframe Detection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-829", CWEName: "Inclusion of Functionality from Untrusted Control Sphere",
		CVSSBase: "High",
	},
	"Cryptocurrency Miner Detection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-506", CWEName: "Embedded Malicious Code",
		CVSSBase: "Critical",
	},
	"Suspicious Redirect Detection": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-601", CWEName: "URL Redirection to Untrusted Site (Open Redirect)",
		CVSSBase: "High",
	},
	"Malware Signature Detection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-506", CWEName: "Embedded Malicious Code",
		CVSSBase: "Critical",
	},
	"Malicious External Links": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-829", CWEName: "Inclusion of Functionality from Untrusted Control Sphere",
		CVSSBase: "Medium",
	},

	// =========================================================================
	// Threat Intelligence Scanner
	// =========================================================================
	"Cryptojacking Detection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-506", CWEName: "Embedded Malicious Code",
		CVSSBase: "Critical",
	},
	"C2 Server Communication": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-506", CWEName: "Embedded Malicious Code",
		CVSSBase: "Critical",
	},
	"Blacklist Check": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-290", CWEName: "Authentication Bypass by Spoofing",
		CVSSBase: "High",
	},
	"Domain Reputation & Age": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-290", CWEName: "Authentication Bypass by Spoofing",
		CVSSBase: "Informational",
	},

	// =========================================================================
	// SEO Scanner (informational - no OWASP/CWE)
	// =========================================================================
	"Meta Tags Quality": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Open Graph Tags": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Sitemap Accessibility": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Robots.txt Quality": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Structured Data": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Mobile Friendliness": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},

	// =========================================================================
	// Third-Party Scripts Scanner
	// =========================================================================
	"External Script Count": {
		OWASP: "A08:2021", OWASPName: "Software and Data Integrity Failures",
		CWE: "CWE-829", CWEName: "Inclusion of Functionality from Untrusted Control Sphere",
		CVSSBase: "Medium",
	},
	"Subresource Integrity (SRI)": {
		OWASP: "A08:2021", OWASPName: "Software and Data Integrity Failures",
		CWE: "CWE-353", CWEName: "Missing Support for Integrity Check",
		CVSSBase: "Medium",
	},
	"Trusted Sources": {
		OWASP: "A08:2021", OWASPName: "Software and Data Integrity Failures",
		CWE: "CWE-829", CWEName: "Inclusion of Functionality from Untrusted Control Sphere",
		CVSSBase: "Medium",
	},
	"External CSS Count": {
		OWASP: "A08:2021", OWASPName: "Software and Data Integrity Failures",
		CWE: "CWE-829", CWEName: "Inclusion of Functionality from Untrusted Control Sphere",
		CVSSBase: "Low",
	},

	// =========================================================================
	// JavaScript Libraries Scanner
	// =========================================================================
	"Outdated jQuery Detection": {
		OWASP: "A06:2021", OWASPName: "Vulnerable and Outdated Components",
		CWE: "CWE-1104", CWEName: "Use of Unmaintained Third Party Components",
		CVSSBase: "Medium",
	},
	"Known Vulnerable Libraries": {
		OWASP: "A06:2021", OWASPName: "Vulnerable and Outdated Components",
		CWE: "CWE-1104", CWEName: "Use of Unmaintained Third Party Components",
		CVSSBase: "High",
	},
	"Inline Script Analysis": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "Medium",
	},

	// =========================================================================
	// WordPress Scanner
	// =========================================================================
	"WordPress Version": {
		OWASP: "A06:2021", OWASPName: "Vulnerable and Outdated Components",
		CWE: "CWE-1104", CWEName: "Use of Unmaintained Third Party Components",
		CVSSBase: "High",
	},
	"WP Login Page Exposure": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-307", CWEName: "Improper Restriction of Excessive Authentication Attempts",
		CVSSBase: "Medium",
	},
	"WP XML-RPC Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-749", CWEName: "Exposed Dangerous Method or Function",
		CVSSBase: "Critical",
	},
	"WP REST API User Enumeration": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Medium",
	},
	"WP Readme/License Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Low",
	},
	"WP Debug Mode": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-209", CWEName: "Generation of Error Message Containing Sensitive Information",
		CVSSBase: "Critical",
	},

	// =========================================================================
	// XSS Vulnerability Scanner
	// =========================================================================
	"Reflected XSS Detection": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "High",
	},
	"DOM-Based XSS Indicators": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "High",
	},
	"Input Sanitization Check": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "High",
	},
	"Content-Type & X-XSS-Protection Headers": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "Medium",
	},
	"URL Parameter Reflection Analysis": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-79", CWEName: "Improper Neutralization of Input During Web Page Generation (XSS)",
		CVSSBase: "High",
	},

	// =========================================================================
	// Secrets Detection Scanner
	// =========================================================================
	"API Key Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-798", CWEName: "Use of Hard-coded Credentials",
		CVSSBase: "Critical",
	},
	"Private Key Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-312", CWEName: "Cleartext Storage of Sensitive Information",
		CVSSBase: "Critical",
	},
	"Database Connection String Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Critical",
	},
	"Email/Password Exposure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-312", CWEName: "Cleartext Storage of Sensitive Information",
		CVSSBase: "High",
	},

	// =========================================================================
	// Subdomain Discovery Scanner
	// =========================================================================
	"Common Subdomain Enumeration": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Informational",
	},
	"Subdomain Security Check": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "Medium",
	},
	"Dangling DNS / Subdomain Takeover Risk": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-16", CWEName: "Configuration",
		CVSSBase: "High",
	},

	// =========================================================================
	// Technology Detection Scanner (informational)
	// =========================================================================
	"Web Framework Detection": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Server Technology Detection": {
		OWASP: "", OWASPName: "Informational",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "Informational",
	},
	"JavaScript Library Inventory": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},

	// --- SQL Injection ---
	"SQL Injection Test": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-89", CWEName: "SQL Injection",
		CVSSBase: "Critical",
	},
	"Database Error Disclosure": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-209", CWEName: "Generation of Error Message Containing Sensitive Information",
		CVSSBase: "High",
	},

	// --- Port Scanner ---
	"Open Port Detection": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "High",
	},

	// --- Blind SQL Injection ---
	"Blind SQL Injection Test": {
		OWASP: "A03:2021", OWASPName: "Injection",
		CWE: "CWE-89", CWEName: "SQL Injection",
		CVSSBase: "Critical",
	},

	// --- Open Redirect ---
	"Open Redirect Test": {
		OWASP: "A01:2021", OWASPName: "Broken Access Control",
		CWE: "CWE-601", CWEName: "URL Redirection to Untrusted Site",
		CVSSBase: "Medium",
	},

	// --- SSRF ---
	"SSRF Detection": {
		OWASP: "A10:2021", OWASPName: "Server-Side Request Forgery",
		CWE: "CWE-918", CWEName: "Server-Side Request Forgery (SSRF)",
		CVSSBase: "High",
	},

	// --- Email Security ---
	"DKIM Record": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-290", CWEName: "Authentication Bypass by Spoofing",
		CVSSBase: "Medium",
	},
	"BIMI Record": {
		OWASP: "", OWASPName: "Informational",
		CWE: "", CWEName: "",
		CVSSBase: "Informational",
	},
	"Email Security Score": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-290", CWEName: "Authentication Bypass by Spoofing",
		CVSSBase: "Medium",
	},

	// --- WAF Fingerprinting ---
	"WAF Detection": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-693", CWEName: "Protection Mechanism Failure",
		CVSSBase: "Medium",
	},

	// --- DNS Zone Transfer ---
	"DNS Zone Transfer": {
		OWASP: "A05:2021", OWASPName: "Security Misconfiguration",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "High",
	},

	// --- Data Leak ---
	"Domain Breach History": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-359", CWEName: "Exposure of Private Personal Information to an Unauthorized Actor",
		CVSSBase: "Critical",
	},
	"Email Breach Detection": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-521", CWEName: "Weak Password Requirements",
		CVSSBase: "High",
	},
	"Paste Site Exposure": {
		OWASP: "A07:2021", OWASPName: "Identification and Authentication Failures",
		CWE: "CWE-200", CWEName: "Exposure of Sensitive Information to an Unauthorized Actor",
		CVSSBase: "High",
	},
}

// GetOWASPMapping returns the OWASP/CWE mapping for a given check name, or nil if not found.
// For dynamically-named checks (e.g., "Cookie: session_id"), it falls back to the
// category-level default mapping.
func GetOWASPMapping(checkName string) *OWASPMapping {
	if m, ok := CheckOWASPMap[checkName]; ok {
		return &m
	}

	// Handle dynamic cookie check names like "Cookie: session_id"
	if len(checkName) > 8 && checkName[:8] == "Cookie: " {
		m := CheckOWASPMap["Cookie Security"]
		return &m
	}

	return nil
}
