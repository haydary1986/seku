# VScan Scanner Documentation — Complete Technical Reference

> **Version:** 1.0
> **Last Updated:** 2026-03-25
> **Engine:** VScan-MOHESR Batch Vulnerability Scanner
> **Scoring Scale:** 0–1000 per check (weighted average for overall score)

---

## Table of Contents

- [Scoring Methodology](#scoring-methodology)
- [Plan Availability Matrix](#plan-availability-matrix)
- [Scan Policy Descriptions](#scan-policy-descriptions)
- [Scanner Summary Table](#scanner-summary-table)
- [1. SSL/TLS Scanner](#1-ssltls-scanner)
- [2. Security Headers Scanner](#2-security-headers-scanner)
- [3. Cookie Security Scanner](#3-cookie-security-scanner)
- [4. Server Information Scanner](#4-server-information-scanner)
- [5. Directory Listing Scanner](#5-directory-listing-scanner)
- [6. Performance Scanner](#6-performance-scanner)
- [7. DDoS Protection Scanner](#7-ddos-protection-scanner)
- [8. CORS Configuration Scanner](#8-cors-configuration-scanner)
- [9. HTTP Methods Scanner](#9-http-methods-scanner)
- [10. DNS Security Scanner](#10-dns-security-scanner)
- [11. Mixed Content Scanner](#11-mixed-content-scanner)
- [12. Information Disclosure Scanner](#12-information-disclosure-scanner)
- [13. Content Optimization Scanner](#13-content-optimization-scanner)
- [14. Hosting Quality Scanner](#14-hosting-quality-scanner)
- [15. Advanced Security Scanner](#15-advanced-security-scanner)
- [16. Malware & Threats Scanner](#16-malware--threats-scanner)
- [17. Threat Intelligence Scanner](#17-threat-intelligence-scanner)
- [18. SEO & Technical Health Scanner](#18-seo--technical-health-scanner)
- [19. Third-Party Scripts Risk Scanner](#19-third-party-scripts-risk-scanner)
- [20. JavaScript Library Scanner](#20-javascript-library-scanner)
- [21. WordPress Security Scanner](#21-wordpress-security-scanner)
- [22. XSS Vulnerability Scanner](#22-xss-vulnerability-scanner)
- [23. Secrets Detection Scanner](#23-secrets-detection-scanner)
- [24. Subdomain Discovery Scanner](#24-subdomain-discovery-scanner)
- [25. Technology Detection Scanner](#25-technology-detection-scanner)
- [OWASP Top 10 2021 Coverage Matrix](#owasp-top-10-2021-coverage-matrix)
- [CWE Coverage List](#cwe-coverage-list)
- [CVSS Distribution](#cvss-distribution)

---

## Scoring Methodology

### Score Scale

All individual checks are scored on a **0–1000** point scale:

| Range | Grade | Status | Interpretation |
|-------|-------|--------|----------------|
| 900–1000 | A | pass | Excellent — follows best practices |
| 750–899 | B | pass | Good — minor improvements possible |
| 500–749 | C | warning | Fair — notable issues to address |
| 200–499 | D | warning | Poor — significant problems detected |
| 0–199 | F | fail | Critical — immediate attention required |

### Overall Score Calculation

The overall score for a target is a **weighted average** of all check scores:

```
Overall Score = SUM(check_score * check_weight) / SUM(check_weight)
```

Each scanner has a **scanner-level weight** (e.g., SSL = 20.0) and each check within a scanner has its own **check-level weight**. The check-level weights are used in the overall calculation.

### Severity Levels

| Severity | Meaning |
|----------|---------|
| `critical` | Immediate security risk; exploitation is trivial |
| `high` | Significant vulnerability; should be fixed urgently |
| `medium` | Notable issue; should be addressed in the near term |
| `low` | Minor concern; fix when convenient |
| `info` | Informational finding; no action required |

### Confidence Levels

Each check has a confidence percentage reflecting detection reliability:

| Confidence | Meaning |
|------------|---------|
| 100% | Deterministic — header present/absent, version exact match |
| 85–95% | High confidence — reliable pattern matching |
| 70–80% | Medium confidence — heuristic detection |
| 60% | Lower confidence — network-dependent or indirect indicators |

---

## Plan Availability Matrix

| # | Scanner (Category) | Free | Basic | Pro | Enterprise |
|---|-------------------|:----:|:-----:|:---:|:----------:|
| 1 | SSL/TLS (`ssl`) | Yes | Yes | Yes | Yes |
| 2 | Security Headers (`headers`) | Yes | Yes | Yes | Yes |
| 3 | Cookie Security (`cookies`) | Yes | Yes | Yes | Yes |
| 4 | Server Information (`server_info`) | - | Yes | Yes | Yes |
| 5 | Directory Listing (`directory`) | - | Yes | Yes | Yes |
| 6 | Performance (`performance`) | Yes | Yes | Yes | Yes |
| 7 | DDoS Protection (`ddos`) | - | Yes | Yes | Yes |
| 8 | CORS Configuration (`cors`) | - | Yes | Yes | Yes |
| 9 | HTTP Methods (`http_methods`) | - | Yes | Yes | Yes |
| 10 | DNS Security (`dns`) | - | Yes | Yes | Yes |
| 11 | Mixed Content (`mixed_content`) | Yes | Yes | Yes | Yes |
| 12 | Information Disclosure (`info_disclosure`) | - | - | Yes | Yes |
| 13 | Content Optimization (`content`) | - | - | Yes | Yes |
| 14 | Hosting Quality (`hosting`) | - | - | Yes | Yes |
| 15 | Advanced Security (`advanced_security`) | - | - | - | Yes |
| 16 | Malware & Threats (`malware`) | - | - | - | Yes |
| 17 | Threat Intelligence (`threat_intel`) | - | - | - | Yes |
| 18 | SEO & Technical Health (`seo`) | - | Yes | Yes | Yes |
| 19 | Third-Party Scripts (`third_party`) | - | - | Yes | Yes |
| 20 | JavaScript Libraries (`js_libraries`) | - | - | Yes | Yes |
| 21 | WordPress Security (`wordpress`) | - | - | Yes | Yes |
| 22 | XSS Vulnerability (`xss`) | - | - | Yes | Yes |
| 23 | Secrets Detection (`secrets`) | - | Yes | Yes | Yes |
| 24 | Subdomain Discovery (`subdomains`) | - | - | Yes | Yes |
| 25 | Technology Detection (`tech_stack`) | - | - | Yes | Yes |

**Category counts:** Free = 5, Basic = 13, Pro = 22, Enterprise = 25

---

## Scan Policy Descriptions

Scan policies are independent of plan tiers. They control *which categories* run in a given scan job.

| Policy | Name | Categories | Timeout | Description |
|--------|------|:----------:|:-------:|-------------|
| `light` | Light Scan | 8 | 30s | Quick security check — ssl, headers, cookies, mixed_content, performance, dns, seo, content |
| `standard` | Standard Scan | 16 | 60s | Comprehensive audit — adds server_info, directory, ddos, cors, http_methods, info_disclosure, hosting, secrets |
| `deep` | Deep Scan | 25 (all) | 120s | Full assessment — adds advanced_security, malware, threat_intel, third_party, js_libraries, wordpress, xss, subdomains, tech_stack |

---

## Scanner Summary Table

| # | Scanner Name | Category | Weight | Checks | OWASP Coverage |
|---|-------------|----------|:------:|:------:|---------------|
| 1 | SSL/TLS Scanner | `ssl` | 20.0 | 4 | A02:2021 |
| 2 | Security Headers Scanner | `headers` | 20.0 | 7 | A01, A03, A05 |
| 3 | Cookie Security Scanner | `cookies` | 10.0 | Dynamic | A01:2021 |
| 4 | Server Information Scanner | `server_info` | 15.0 | 3 | A05:2021 |
| 5 | Directory Listing Scanner | `directory` | 10.0 | 9 | A01, A05 |
| 6 | Performance Scanner | `performance` | 15.0 | 3 | A05:2021 |
| 7 | DDoS Protection Scanner | `ddos` | 10.0 | 3 | A04, A05 |
| 8 | CORS Configuration Scanner | `cors` | 10.0 | 2 | A01:2021 |
| 9 | HTTP Methods Scanner | `http_methods` | 8.0 | 2 | A05:2021 |
| 10 | DNS Security Scanner | `dns` | 8.0 | 3 | A02, A07 |
| 11 | Mixed Content Scanner | `mixed_content` | 7.0 | 3 | A02:2021 |
| 12 | Information Disclosure Scanner | `info_disclosure` | 7.0 | 3 | A05:2021 |
| 13 | Content Optimization Scanner | `content` | 8.0 | 3 | Informational |
| 14 | Hosting Quality Scanner | `hosting` | 12.0 | 6 | Informational |
| 15 | Advanced Security Scanner | `advanced_security` | 5.0 | 4 | A01, A02 |
| 16 | Malware & Threats Scanner | `malware` | 10.0 | 6 | A01, A03 |
| 17 | Threat Intelligence Scanner | `threat_intel` | 8.0 | 4 | A03, A07 |
| 18 | SEO & Technical Health Scanner | `seo` | 7.0 | 6 | Informational |
| 19 | Third-Party Scripts Risk Scanner | `third_party` | 6.0 | 4 | A08:2021 |
| 20 | JavaScript Library Scanner | `js_libraries` | 6.0 | 3 | A03, A06 |
| 21 | WordPress Security Scanner | `wordpress` | 8.0 | 6 | A01, A05, A06, A07 |
| 22 | XSS Vulnerability Scanner | `xss` | 9.0 | 5 | A03:2021 |
| 23 | Secrets Detection Scanner | `secrets` | 8.0 | 4 | A05:2021 |
| 24 | Subdomain Discovery Scanner | `subdomains` | 5.0 | 3 | A05:2021 |
| 25 | Technology Detection Scanner | `tech_stack` | 4.0 | 3 | Informational |

**Total checks across all scanners: 100+** (cookie checks are dynamic per cookie found)

---

## 1. SSL/TLS Scanner

**Category:** `ssl` | **Weight:** 20.0 | **Checks:** 4

Evaluates the SSL/TLS security configuration of the target website, including HTTPS availability, certificate validity, TLS protocol version, and HTTP-to-HTTPS redirect behavior.

### 1.1 HTTPS Enabled

- **Check Weight:** 50
- **What it checks:** Whether the website is accessible via HTTPS.
- **How it works:** Sends an HTTP GET request to `https://target` with a 10-second timeout (certificate verification skipped to test connectivity). Measures connection time.
- **Scoring:**

  | Condition | Score | Severity | Status |
  |-----------|:-----:|----------|--------|
  | HTTPS available, response time > 5000ms | 800 | low | warning |
  | HTTPS available, response time <= 5000ms | 1000 | info | pass |
  | HTTPS not available (connection error) | 0 | critical | fail |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-319 Cleartext Transmission of Sensitive Information
- **CVSS:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Confidence:** 100%
- **Remediation:** Enable HTTPS by installing an SSL/TLS certificate. Free certificates are available from Let's Encrypt. Ensure your web server is configured to listen on port 443.

### 1.2 Certificate Validity

- **Check Weight:** 50
- **What it checks:** Whether the SSL certificate is valid, not expired, not self-signed, and how many days remain until expiry.
- **How it works:** Establishes a TLS connection to `host:443`, inspects the peer certificate's NotBefore/NotAfter dates, issuer, subject, DNS names, and checks if the certificate is self-signed (issuer == subject with valid self-signature).
- **Scoring:**

  | Condition | Score | Severity | Status |
  |-----------|:-----:|----------|--------|
  | Cannot establish TLS connection | 0 | critical | fail |
  | No certificates found | 0 | critical | fail |
  | Certificate expired or not yet valid | 0 | critical | fail |
  | Self-signed certificate | 400 | medium | warning |
  | Valid, > 90 days until expiry | 1000 | info | pass |
  | Valid, 61–90 days until expiry | 900 | info | pass |
  | Valid, 31–60 days until expiry | 750 | low | pass |
  | Valid, 15–30 days until expiry | 500 | medium | warning |
  | Valid, 8–14 days until expiry | 300 | high | warning |
  | Valid, <= 7 days until expiry | 150 | high | warning |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-295 Improper Certificate Validation
- **CVSS:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Confidence:** 100%
- **Remediation:** Renew certificates before expiry. Replace self-signed certificates with CA-signed ones. Use automated renewal tools (e.g., certbot for Let's Encrypt).

### 1.3 TLS Version

- **Check Weight:** 50
- **What it checks:** Which TLS protocol version the server negotiates, and whether the cipher suite is strong.
- **How it works:** Establishes a TLS connection and reads `ConnectionState().Version` and `ConnectionState().CipherSuite`. Strong cipher suites are AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange.
- **Scoring:**

  | Condition | Score | Severity | Status |
  |-----------|:-----:|----------|--------|
  | TLS 1.3 | 1000 | info | pass |
  | TLS 1.2 with strong cipher suite (AEAD+ECDHE) | 850 | info | pass |
  | TLS 1.2 with weak cipher suite | 700 | low | pass |
  | TLS 1.1 (deprecated) | 200 | high | warning |
  | TLS 1.0 or older | 0 | critical | fail |
  | Connection error | 0 | high | error |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-326 Inadequate Encryption Strength
- **CVSS:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Confidence:** 100%
- **Remediation:** Configure the server to support TLS 1.2+ only. Disable TLS 1.0 and 1.1. Prefer TLS 1.3. Use strong cipher suites (ECDHE + AEAD).

### 1.4 HTTP to HTTPS Redirect

- **Check Weight:** 50
- **What it checks:** Whether HTTP requests are redirected to HTTPS, and which redirect status code is used.
- **How it works:** Sends a GET request to `http://target` with redirect following disabled. Checks if the response is a 3xx redirect to an HTTPS URL. Falls back to checking if HTTPS is available directly if HTTP is unreachable.
- **Scoring:**

  | Condition | Score | Severity | Status |
  |-----------|:-----:|----------|--------|
  | 301 redirect to HTTPS (permanent) | 1000 | info | pass |
  | 302 redirect to HTTPS (temporary) | 850 | low | pass |
  | Other 3xx redirect to HTTPS | 700 | low | pass |
  | No redirect, but HTTPS available separately | 400 | medium | warning |
  | HTTP unreachable, HTTPS works directly | 400 | medium | warning |
  | Neither HTTP nor HTTPS reachable | 0 | high | fail |
  | HTTP does not redirect and HTTPS not available | 0 | high | fail |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-319 Cleartext Transmission of Sensitive Information
- **CVSS:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Confidence:** 100%
- **Remediation:** Configure a 301 permanent redirect from HTTP to HTTPS on all paths. In Apache: `RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]`. In Nginx: `return 301 https://$host$request_uri;`.

---

## 2. Security Headers Scanner

**Category:** `headers` | **Weight:** 20.0 | **Checks:** 7

Evaluates essential HTTP security response headers that protect against common web attacks.

### 2.1 HSTS (Strict-Transport-Security)

- **Check Weight:** 5.0
- **What it checks:** Presence and configuration of the `Strict-Transport-Security` header.
- **How it works:** Fetches the target page via HTTPS (fallback to HTTP) and inspects the `Strict-Transport-Security` header. Parses `max-age`, checks for `includeSubDomains` and `preload` directives.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | critical |
  | max-age = 0 (effectively disabled) | 100 | — |
  | max-age < 6 months (15768000s) | 400 | — |
  | max-age >= 6 months but < 1 year | 650 | — |
  | max-age >= 1 year, no includeSubDomains | 800 | — |
  | max-age >= 1 year + includeSubDomains, no preload | 920 | — |
  | max-age >= 1 year + includeSubDomains + preload | 1000 | — |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-523 Unprotected Transport of Credentials
- **CVSS:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Confidence:** 100%
- **Remediation:** Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

### 2.2 Content Security Policy

- **Check Weight:** 5.0
- **What it checks:** Presence and strength of the `Content-Security-Policy` header.
- **How it works:** Checks for the CSP header, then evaluates whether it uses `default-src *` (too permissive), `unsafe-inline`, or `unsafe-eval`.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | high |
  | Too permissive (`default-src *`) | 200 | — |
  | Has both `unsafe-inline` and `unsafe-eval` | 400 | — |
  | Has `unsafe-inline` only (no `unsafe-eval`) | 700 | — |
  | Specific sources, no unsafe directives | 1000 | — |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 Improper Neutralization of Input During Web Page Generation (XSS)
- **CVSS:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Confidence:** 100%
- **Remediation:** Implement a restrictive CSP. Start with `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'` and expand as needed.

### 2.3 X-Frame-Options

- **Check Weight:** 3.0
- **What it checks:** Presence and value of the `X-Frame-Options` header (clickjacking protection).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | high |
  | Value: `DENY` | 1000 | — |
  | Value: `SAMEORIGIN` | 900 | — |
  | Value: `ALLOW-FROM <origin>` | 700 | — |
  | Unrecognized value | 400 | — |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-1021 Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
- **CVSS:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Confidence:** 100%
- **Remediation:** Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.

### 2.4 X-Content-Type-Options

- **Check Weight:** 3.0
- **What it checks:** Whether the `X-Content-Type-Options: nosniff` header is set to prevent MIME type sniffing.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | medium |
  | Value: `nosniff` | 1000 | — |
  | Other value | 400 | — |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-16 Configuration
- **Confidence:** 100%
- **Remediation:** Add `X-Content-Type-Options: nosniff`.

### 2.5 X-XSS-Protection

- **Check Weight:** 2.0
- **What it checks:** Legacy XSS protection header (modern browsers use CSP instead).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | medium |
  | `1; mode=block` | 1000 | — |
  | `1` (without mode=block) | 700 | — |
  | `0` (intentionally disabled) | 500 | — |
  | Unrecognized value | 300 | — |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 XSS
- **Confidence:** 100%
- **Remediation:** Add `X-XSS-Protection: 1; mode=block` or rely on a strong CSP.

### 2.6 Referrer-Policy

- **Check Weight:** 2.0
- **What it checks:** How much referrer information is shared with external sites.
- **How it works:** Reads the `Referrer-Policy` header. If multiple comma-separated policies, uses the last one (browser behavior).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | medium |
  | `no-referrer` or `same-origin` | 1000 | — |
  | `strict-origin-when-cross-origin` | 900 | — |
  | `strict-origin` | 850 | — |
  | `origin-when-cross-origin` | 600 | — |
  | `origin` | 500 | — |
  | `no-referrer-when-downgrade` | 400 | — |
  | `unsafe-url` | 100 | — |
  | Unrecognized value | 300 | — |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
- **Confidence:** 100%
- **Remediation:** Add `Referrer-Policy: strict-origin-when-cross-origin` (recommended) or `no-referrer`.

### 2.7 Permissions-Policy

- **Check Weight:** 2.0
- **What it checks:** Whether the `Permissions-Policy` header is present and restrictive.
- **How it works:** Checks for wildcard (`=*`) allowlists and whether restriction directives (`=()` or `=(self)`) are present.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 0 | medium |
  | Permissive (wildcard or no restriction directives) | 500 | — |
  | Restrictive settings | 1000 | — |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-250 Execution with Unnecessary Privileges
- **CVSS:** 4.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
- **Confidence:** 100%
- **Remediation:** Add `Permissions-Policy: camera=(), microphone=(), geolocation=()` to disable unnecessary browser features.

---

## 3. Cookie Security Scanner

**Category:** `cookies` | **Weight:** 10.0 | **Checks:** Dynamic (1 per cookie)

Evaluates the security attributes of all cookies set in the initial HTTP response.

### 3.1 Cookie: {name} (per cookie)

- **Check Weight:** `10.0 / number_of_cookies`
- **What it checks:** Whether each cookie has the `Secure`, `HttpOnly`, and `SameSite` attributes.
- **How it works:** Fetches the page (HTTPS first, then HTTP fallback), parses `Set-Cookie` headers, evaluates each cookie's security flags.
- **Scoring:** Starts at 1000, penalties applied:

  | Missing Flag | Penalty | Risk |
  |-------------|:-------:|------|
  | Missing `Secure` flag | -350 | Cookie sent over insecure HTTP |
  | Missing `HttpOnly` flag | -325 | Cookie accessible to JavaScript (XSS risk) |
  | Missing `SameSite` attribute | -325 | Cookie vulnerable to CSRF |

  Minimum score: 0. If no cookies are found, a single check returns score 1000 ("No cookies set on initial response").

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-614 Sensitive Cookie in HTTPS Session Without Secure Attribute
- **Confidence:** 100%
- **Remediation:** Set all cookies with `Secure; HttpOnly; SameSite=Strict` (or `SameSite=Lax` if cross-site navigation is needed).

---

## 4. Server Information Scanner

**Category:** `server_info` | **Weight:** 15.0 | **Checks:** 3

Evaluates how much server technology information is exposed through HTTP headers and known CMS paths.

### 4.1 Server Header Exposure

- **Check Weight:** 5.0
- **What it checks:** Whether the `Server` header reveals software name and/or version.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header not present | 1000 | info |
  | CDN/WAF proxy name (Cloudflare, Fastly, etc.) | 900 | info |
  | Exposes name with version numbers | 250 | high |
  | Exposes known server name (Apache/Nginx/IIS/LiteSpeed) without version | 450 | medium |
  | Present with generic value | 650 | low |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200 Exposure of Sensitive Information
- **Confidence:** 95%
- **Remediation:** Remove or obfuscate the Server header. In Nginx: `server_tokens off;`. In Apache: `ServerTokens Prod`.

### 4.2 X-Powered-By Exposure

- **Check Weight:** 5.0
- **What it checks:** Whether the `X-Powered-By` header exposes the technology stack.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header not present | 1000 | info |
  | Exposes technology with version | 125 | high |
  | Exposes technology without version | 225 | high |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200 Exposure of Sensitive Information
- **Confidence:** 100%
- **Remediation:** Remove the X-Powered-By header. In Express.js: `app.disable('x-powered-by')`. In PHP: `expose_php = Off`.

### 4.3 CMS Detection

- **Check Weight:** 5.0
- **What it checks:** Whether a common CMS (WordPress, Joomla, Drupal, Moodle) is detectable.
- **How it works:** Probes known CMS-specific paths (e.g., `/wp-login.php`, `/administrator/`, `/core/misc/drupal.js`, `/login/index.php`) and checks the `X-Generator` header.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No CMS detected | 1000 | info |
  | WordPress detected | 550 | — |
  | Joomla detected | 600 | — |
  | Moodle detected | 625 | — |
  | Drupal detected | 650 | — |
  | Other CMS | 600 | — |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200 Exposure of Sensitive Information
- **Confidence:** 70%
- **Remediation:** Hide CMS-specific paths where possible. Use security plugins to mask CMS signatures.

---

## 5. Directory Listing Scanner

**Category:** `directory` | **Weight:** 10.0 | **Checks:** 9

Probes for sensitive files and directories that should not be publicly accessible.

### Check Details

Each of the 9 paths below is checked. **Check Weight** per path: `10.0 / 9 ≈ 1.11`.

| Path | Check Name | Base Severity |
|------|-----------|:-------------:|
| `/robots.txt` | Robots.txt Exposure | info |
| `/.env` | Environment File Exposure | critical |
| `/.git/config` | Git Repository Exposure | critical |
| `/phpinfo.php` | PHP Info Exposure | high |
| `/admin/` | Admin Panel Exposure | high |
| `/backup/` | Backup Directory Exposure | critical |
| `/.htaccess` | Htaccess File Exposure | high |
| `/wp-config.php.bak` | WordPress Config Backup | critical |
| `/server-status` | Server Status Exposure | high |

**Scoring per path:**

| Condition | Score | Notes |
|-----------|:-----:|-------|
| Path not accessible (error or non-200/403) | 1000 | Path not found |
| robots.txt with disallow rules | 875 | Expected file |
| robots.txt with minimal content | 925 | Expected file |
| 200 with directory listing ("Index of") | 0 | Worst case |
| 200, critical severity path accessible | 50 | e.g., .env, .git, backup |
| 200, high severity path accessible | 125 | e.g., phpinfo, admin |
| 200, other severity | 175 | — |
| 403 with WAF/CDN protection headers | 900 | Well protected |
| 403 without WAF indicators | 725 | Path exists but forbidden |

- **OWASP:** A05:2021 / A01:2021 (varies by path)
- **CWE:** CWE-538 / CWE-425
- **CVSS:** 7.5 (High) for .env and .git — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Confidence:** 80–100% depending on path
- **Remediation:** Block access to sensitive files in web server configuration. Add rules to deny access to `.env`, `.git`, backup files, and admin panels.

---

## 6. Performance Scanner

**Category:** `performance` | **Weight:** 15.0 | **Checks:** 3

Measures website response speed and TLS handshake performance using piecewise linear scoring.

### 6.1 Response Time

- **Check Weight:** 50.0
- **What it checks:** Total time from request to response completion.
- **Scoring (piecewise linear interpolation):**

  | Response Time (ms) | Score Range |
  |-------------------:|:-----------:|
  | <= 200 | 1000 |
  | 200–500 | 1000–900 |
  | 500–1000 | 900–750 |
  | 1000–2000 | 750–500 |
  | 2000–5000 | 500–200 |
  | 5000–10000 | 200–50 |
  | > 10000 | 0 |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-400 Uncontrolled Resource Consumption
- **Confidence:** 60%

### 6.2 Time to First Byte (TTFB)

- **Check Weight:** 50.0
- **What it checks:** Time from sending request to receiving the first byte of response. Uses `httptrace` for precise measurement of DNS, connect, and first-byte timing.
- **Scoring (piecewise linear interpolation):**

  | TTFB (ms) | Score Range |
  |----------:|:-----------:|
  | <= 100 | 1000 |
  | 100–200 | 1000–920 |
  | 200–500 | 920–750 |
  | 500–1000 | 750–450 |
  | 1000–2000 | 450–200 |
  | 2000–5000 | 200–50 |
  | > 5000 | 0 |

- **Confidence:** 60%

### 6.3 TLS Handshake Time

- **Check Weight:** 50.0
- **What it checks:** Duration of the TLS handshake.
- **Scoring (piecewise linear interpolation):**

  | TLS Handshake (ms) | Score Range |
  |-------------------:|:-----------:|
  | <= 50 | 1000 |
  | 50–100 | 1000–920 |
  | 100–300 | 920–750 |
  | 300–700 | 750–450 |
  | 700–1500 | 450–150 |
  | > 1500 | 50 |

- **Confidence:** 60%
- **Remediation:** Use a CDN, enable HTTP/2, optimize server configuration, use OCSP stapling to reduce TLS handshake time.

---

## 7. DDoS Protection Scanner

**Category:** `ddos` | **Weight:** 10.0 | **Checks:** 3

Detects CDN/DDoS protection services, rate limiting headers, and Web Application Firewall (WAF) presence.

### 7.1 CDN/DDoS Protection Service

- **Check Weight:** 4.0
- **What it checks:** Presence of known CDN and DDoS protection service headers.
- **Detection:** Checks for Cloudflare (`CF-RAY`), AWS CloudFront (`X-Amz-Cf-Id`), Akamai (`X-Akamai-Transformed`), Fastly (`X-Fastly-Request-ID`), Sucuri (`X-Sucuri-ID`), Imperva (`X-CDN`/`X-Iinfo`), Azure Front Door (`X-Azure-Ref`), Google Cloud CDN (`X-Goog-Component`).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No CDN detected | 0 | critical |
  | Generic CDN detected | 750 | — |
  | Sucuri | 925 | — |
  | Fastly / Imperva / Azure / Google Cloud | 950 | — |
  | AWS CloudFront / Akamai | 975 | — |
  | Cloudflare | 1000 | — |
  | Multiple providers: +25 bonus (max 1000) | — | — |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-770 Allocation of Resources Without Limits or Throttling
- **Confidence:** 85%

### 7.2 Rate Limiting

- **Check Weight:** 3.0
- **What it checks:** Presence of rate limiting headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`, etc.).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No rate limiting headers | 250 | high |
  | 1 header found | 700 | low |
  | 2 headers found | 850 | info |
  | 3+ headers found (comprehensive) | 1000 | info |

- **OWASP:** A04:2021 Insecure Design
- **CWE:** CWE-770 Allocation of Resources Without Limits or Throttling
- **Confidence:** 70%

### 7.3 Web Application Firewall (WAF)

- **Check Weight:** 3.0
- **What it checks:** Presence of WAF indicators via headers and behavioral testing.
- **How it works:** Checks response headers for known WAF signatures (ModSecurity, Sucuri, Imperva, Cloudflare). Also sends a test request with a suspicious XSS parameter (`?test=<script>alert(1)</script>`) to check if the WAF blocks it.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No WAF detected | 75 | critical |
  | WAF block page detected | 875 | — |
  | Blocked suspicious request (403/406/429) | 900 | — |
  | ModSecurity detected | 925 | — |
  | Sucuri WAF | 950 | — |
  | Imperva WAF | 975 | — |
  | Cloudflare WAF | 1000 | — |
  | Multiple WAF indicators: +50 bonus (max 1000) | — | — |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-693 Protection Mechanism Failure
- **Confidence:** 75%
- **Remediation:** Deploy a WAF service (Cloudflare, AWS WAF, ModSecurity) in front of your web application.

---

## 8. CORS Configuration Scanner

**Category:** `cors` | **Weight:** 10.0 | **Checks:** 2

Evaluates Cross-Origin Resource Sharing (CORS) configuration by sending OPTIONS requests with a malicious origin.

### 8.1 CORS Wildcard Origin

- **Check Weight:** 5.0
- **What it checks:** Whether the server reflects arbitrary origins or uses wildcard `*` in `Access-Control-Allow-Origin`.
- **How it works:** Sends an OPTIONS request with `Origin: https://evil-attacker.com` and checks the `Access-Control-Allow-Origin` response header.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Reflects arbitrary origin (`https://evil-attacker.com`) | 0 | critical |
  | Wildcard `*` | 375 | medium |
  | Specific origin configured | 925 | info |
  | No CORS header to foreign origins | 1000 | info |
  | Cannot perform check | 825 | info |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-942 Permissive Cross-domain Policy with Untrusted Domains
- **CVSS:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Confidence:** 100%

### 8.2 CORS Credentials

- **Check Weight:** 5.0
- **What it checks:** Whether `Access-Control-Allow-Credentials: true` is set alongside permissive origins.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Credentials with wildcard/reflected origin | 0 | critical |
  | Credentials with specific origin | 575 | medium |
  | Credentials header present, no origin reflected | 725 | low |
  | Secure configuration | 1000 | info |
  | Cannot perform check | 825 | info |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-942 Permissive Cross-domain Policy with Untrusted Domains
- **Confidence:** 100%
- **Remediation:** Never use `Access-Control-Allow-Origin: *` with credentials. Whitelist specific trusted origins.

---

## 9. HTTP Methods Scanner

**Category:** `http_methods` | **Weight:** 8.0 | **Checks:** 2

Tests whether dangerous HTTP methods are enabled and whether OPTIONS reveals method information.

### 9.1 Dangerous HTTP Methods

- **Check Weight:** 4.0
- **What it checks:** Whether TRACE, DELETE, PUT, PATCH methods are accepted (not returning 405/501/403).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | All disabled (405/501/403 for all) | 1000 | info |
  | 1 dangerous method enabled | 275 | high |
  | 2 dangerous methods enabled | 175 | high |
  | 3+ dangerous methods enabled | 75 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-749 Exposed Dangerous Method or Function
- **CVSS:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **Confidence:** 95%

### 9.2 OPTIONS Method Disclosure

- **Check Weight:** 4.0
- **What it checks:** Whether an OPTIONS request returns an `Allow` header disclosing available methods.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | OPTIONS not accessible or no Allow header | 1000 | info |
  | Allow header lists only safe methods | 925 | info |
  | Discloses PUT/PATCH methods | 450 | medium |
  | Discloses TRACE/DELETE methods | 375 | medium |
  | Discloses many dangerous methods (TRACE/DELETE + PUT/PATCH) | 225 | high |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-749 Exposed Dangerous Method or Function
- **Confidence:** 100%
- **Remediation:** Disable unnecessary HTTP methods in web server configuration. Block TRACE, DELETE, PUT, PATCH on public endpoints.

---

## 10. DNS Security Scanner

**Category:** `dns` | **Weight:** 8.0 | **Checks:** 3

Evaluates email security DNS records and certificate authority authorization.

### 10.1 SPF Record (Email Security)

- **Check Weight:** 3.0
- **What it checks:** Presence and policy of the SPF (Sender Policy Framework) TXT record.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No SPF record | 0 | critical |
  | Cannot lookup TXT records | 275 | high |
  | SPF with `?all` (neutral) | 450 | medium |
  | SPF with permissive policy | 525 | medium |
  | SPF with `~all` (soft fail) | 725 | low |
  | SPF with `-all` (strict) | 1000 | info |

- **OWASP:** A07:2021 Identification and Authentication Failures
- **CWE:** CWE-290 Authentication Bypass by Spoofing
- **CVSS:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **Confidence:** 100%

### 10.2 DMARC Record (Email Security)

- **Check Weight:** 3.0
- **What it checks:** Presence and policy of the DMARC record at `_dmarc.{domain}`.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No DMARC record | 0 | critical |
  | DMARC with unclear/unknown policy | 325 | medium |
  | DMARC with `p=none` (monitor only) | 375 | medium |
  | DMARC with `p=quarantine` | 825 | info |
  | DMARC with `p=reject` | 1000 | info |

- **OWASP:** A07:2021 Identification and Authentication Failures
- **CWE:** CWE-290 Authentication Bypass by Spoofing
- **CVSS:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **Confidence:** 100%

### 10.3 CAA Record (Certificate Authority)

- **Check Weight:** 2.0
- **What it checks:** Whether the domain has DNS CAA records restricting which CAs can issue certificates.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Cannot resolve domain | 525 | medium |
  | DNS configured, no CAA records | 675 | low |
  | Cannot verify CAA | 525 | medium |
  | Cloudflare DNS (automatic CAA management) | 925 | info |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-295 Improper Certificate Validation
- **Confidence:** 90%
- **Remediation:** Add CAA DNS records specifying authorized certificate authorities: `example.com. CAA 0 issue "letsencrypt.org"`.

---

## 11. Mixed Content Scanner

**Category:** `mixed_content` | **Weight:** 7.0 | **Checks:** 3

Detects HTTP resources loaded on HTTPS pages (mixed content), which undermines the security provided by HTTPS.

### 11.1 Mixed Active Content (Scripts/CSS)

- **Check Weight:** 3.0
- **What it checks:** HTTP-loaded JavaScript (.js) and CSS (.css) files via `src=` or `href=` attributes.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No mixed active content | 1000 | info |
  | 1–2 HTTP scripts/CSS | 150 | high |
  | 3–5 HTTP scripts/CSS | 75 | critical |
  | > 5 HTTP scripts/CSS | 0 | critical |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-319 Cleartext Transmission of Sensitive Information
- **Confidence:** 90%

### 11.2 Mixed Passive Content (Images/Media)

- **Check Weight:** 2.0
- **What it checks:** HTTP-loaded images (.jpg, .png, .gif, .svg, .webp) and media (.mp4, .mp3) via `src=` attributes.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No mixed passive content | 1000 | info |
  | 1–3 HTTP images/media | 475 | medium |
  | 4–10 HTTP images/media | 375 | medium |
  | > 10 HTTP images/media | 275 | high |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-319 Cleartext Transmission
- **Confidence:** 90%

### 11.3 Insecure Form Actions

- **Check Weight:** 2.0
- **What it checks:** Forms with `action="http://..."` attributes. Extra severity if password fields are present.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No insecure form actions | 1000 | info |
  | 1–3 insecure forms (no password) | 150 | high |
  | > 3 insecure forms (no password) | 75 | critical |
  | Insecure forms with password fields | 0 | critical |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-319 Cleartext Transmission
- **Confidence:** 95%
- **Remediation:** Update all resource URLs to use `https://` or protocol-relative `//` URLs. Ensure all form actions use HTTPS.

---

## 12. Information Disclosure Scanner

**Category:** `info_disclosure` | **Weight:** 7.0 | **Checks:** 3

Detects sensitive information leaked through error pages, HTML comments, and technology version headers.

### 12.1 Error Page Information Disclosure

- **Check Weight:** 3.0
- **What it checks:** Whether error pages (404) reveal stack traces, server versions, framework names, file paths, SQL errors, or debug mode.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No sensitive info in error pages | 1000 | info |
  | 1 disclosure type | 225 | high |
  | 2 disclosure types | 125 | high |
  | 3+ disclosure types | 50 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-209 Generation of Error Message Containing Sensitive Information
- **Confidence:** 80%

### 12.2 Sensitive HTML Comments

- **Check Weight:** 2.0
- **What it checks:** HTML comments containing sensitive keywords: password, todo, fixme, hack, bug, secret, api_key, token, admin, debug, database, db_.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No sensitive comments | 1000 | info |
  | Few comments with dev keywords (todo, fixme, bug) | 475 | medium |
  | Many comments (> 3) with concerning keywords | 325 | medium |
  | Comments with critical keywords (password, secret, api_key, token, database) | 175 | high |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-615 Inclusion of Sensitive Information in Source Code Comments
- **Confidence:** 85%

### 12.3 Technology Version Disclosure

- **Check Weight:** 2.0
- **What it checks:** Version info in meta generator tags, jQuery version in source, and version-revealing headers (`X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No disclosures | 1000 | info |
  | Minor in-page disclosures (1-2) | 550 | medium |
  | Multiple in-page disclosures (> 2) | 425 | medium |
  | 1 header-based disclosure | 350 | medium |
  | 2+ header-based disclosures | 225 | high |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200 Exposure of Sensitive Information
- **Confidence:** 75%
- **Remediation:** Remove HTML comments before deployment. Customize error pages to show generic messages. Remove version-revealing headers.

---

## 13. Content Optimization Scanner

**Category:** `content` | **Weight:** 8.0 | **Checks:** 3

Evaluates caching strategy, page size, and compression effectiveness.

### 13.1 Cache Headers

- **Check Weight:** 40.0
- **What it checks:** `Cache-Control`, `ETag`, `Last-Modified`, and `Expires` headers.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Cache-Control max-age > 86400 + ETag/Last-Modified | 1000 |
  | Cache-Control max-age > 86400 (no validators) | 850 |
  | Cache-Control max-age > 3600 | 700 |
  | Cache-Control max-age > 0 | 550 |
  | Cache-Control no-cache/no-store | 800 |
  | Expires only (no Cache-Control) | 500 |
  | No caching headers | 150 |

- **Confidence:** 100%

### 13.2 Page Size

- **Check Weight:** 30.0
- **What it checks:** Total size of the HTML response body (up to 10MB limit).
- **Scoring (piecewise linear):**

  | Size (KB) | Score Range |
  |----------:|:-----------:|
  | < 50 | 1000 |
  | 50–100 | 1000–900 |
  | 100–250 | 900–750 |
  | 250–500 | 750–550 |
  | 500–1024 | 550–300 |
  | 1024–3072 | 300–100 |
  | > 3072 | 50 |

- **Confidence:** 100%

### 13.3 Compression Ratio

- **Check Weight:** 30.0
- **What it checks:** Effectiveness of response compression (Brotli, Gzip, Deflate). Compares compressed vs uncompressed response sizes.
- **Scoring (piecewise linear on ratio):**

  | Ratio (compressed/uncompressed) | Score Range |
  |--------------------------------:|:-----------:|
  | < 0.3 | 1000 |
  | 0.3–0.5 | 1000–750 |
  | 0.5–0.7 | 750–500 |
  | 0.7–0.9 | 500–250 |
  | > 0.9 | 100 |
  | Compression detected but ratio unknown | 800 |
  | No compression | 200 |

- **Confidence:** 85%
- **Remediation:** Enable Gzip or Brotli compression. Set appropriate cache headers with long max-age for static assets. Optimize HTML/CSS/JS to reduce page size.

---

## 14. Hosting Quality Scanner

**Category:** `hosting` | **Weight:** 12.0 | **Checks:** 6

Evaluates modern hosting infrastructure features including protocol support, compression, and network configuration.

### 14.1 HTTP/2 Support

- **Check Weight:** 25
- **What it checks:** Whether the server supports HTTP/2 via ALPN negotiation.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | HTTP/2 negotiated (`h2`) | 1000 |
  | HTTP/1.1 only | 300 |
  | TLS connection failed | 0 |

- **Confidence:** 100%

### 14.2 HTTP/3 (QUIC) Support

- **Check Weight:** 20
- **What it checks:** Presence of `Alt-Svc` header advertising h3 (HTTP/3 over QUIC).
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | HTTP/3 supported (`h3=` or `h3"` in Alt-Svc) | 1000 |
  | Not supported | 400 |

- **Confidence:** 95%

### 14.3 Brotli Compression

- **Check Weight:** 25
- **What it checks:** Which compression algorithm the server uses when `Accept-Encoding: br, gzip, deflate` is sent.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Brotli (`br`) | 1000 |
  | Gzip | 750 |
  | Deflate | 500 |
  | No compression | 100 |

- **Confidence:** 100%

### 14.4 IPv6 Support

- **Check Weight:** 15
- **What it checks:** Whether the domain has AAAA (IPv6) DNS records.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | IPv6 supported (AAAA records found) | 1000 |
  | IPv4 only | 350 |

- **Confidence:** 100%

### 14.5 Keep-Alive

- **Check Weight:** 10
- **What it checks:** Whether persistent connections are enabled.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | HTTP/2 (persistent by default) | 1000 |
  | `Connection: keep-alive` header | 1000 |
  | No explicit header (assumed for HTTP/1.1) | 700 |
  | `Connection: close` header | 300 |

- **Confidence:** 95%

### 14.6 DNS Resolution Time

- **Check Weight:** 25
- **What it checks:** Time to resolve the domain via DNS.
- **Scoring (piecewise linear):**

  | DNS Time (ms) | Score Range |
  |--------------:|:-----------:|
  | <= 20 | 1000 |
  | 20–50 | 1000–920 |
  | 50–100 | 920–800 |
  | 100–200 | 800–600 |
  | 200–500 | 600–300 |
  | > 500 | 100 |

- **Confidence:** 60%
- **Remediation:** Enable HTTP/2 and HTTP/3. Configure Brotli compression. Add IPv6 support. Use a DNS provider with low latency.

---

## 15. Advanced Security Scanner

**Category:** `advanced_security` | **Weight:** 5.0 | **Checks:** 4

Evaluates advanced cross-origin isolation headers and OCSP stapling for TLS certificate revocation.

### 15.1 Cross-Origin-Embedder-Policy (COEP)

- **Check Weight:** 12.0
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 500 | low |
  | `unsafe-none` or unrecognized | 400 | — |
  | `credentialless` | 850 | — |
  | `require-corp` | 1000 | — |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-346 Origin Validation Error
- **Confidence:** 100%

### 15.2 Cross-Origin-Opener-Policy (COOP)

- **Check Weight:** 12.0
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 500 | low |
  | `unsafe-none` or unrecognized | 400 | — |
  | `same-origin-allow-popups` | 800 | — |
  | `same-origin` | 1000 | — |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-346 Origin Validation Error
- **Confidence:** 100%

### 15.3 Cross-Origin-Resource-Policy (CORP)

- **Check Weight:** 12.0
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Header missing | 500 | low |
  | `cross-origin` or unrecognized | 500 | — |
  | `same-site` | 850 | — |
  | `same-origin` | 1000 | — |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-346 Origin Validation Error
- **Confidence:** 100%

### 15.4 OCSP Stapling

- **Check Weight:** 15.0
- **What it checks:** Whether the server includes OCSP stapling data in the TLS handshake.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | OCSP Stapling enabled | 1000 |
  | OCSP Stapling not enabled | 350 |
  | TLS connection failed | 0 |

- **OWASP:** A02:2021 Cryptographic Failures
- **CWE:** CWE-299 Improper Check for Certificate Revocation
- **Confidence:** 90%
- **Remediation:** Enable OCSP stapling in your web server. In Nginx: `ssl_stapling on; ssl_stapling_verify on;`. Add cross-origin isolation headers for enhanced security.

---

## 16. Malware & Threats Scanner

**Category:** `malware` | **Weight:** 10.0 | **Checks:** 6

Detects malicious JavaScript, hidden iframes, cryptocurrency miners, suspicious redirects, malware signatures, and external malicious links.

### 16.1 Malicious JavaScript Detection

- **Check Weight:** 3.0
- **What it checks:** Obfuscated eval() calls, suspicious document.write(), heavily obfuscated scripts (> 5000 chars), String.fromCharCode chains, packed JavaScript (p,a,c,k,e,d).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No threats | 1000 | info |
  | Threats found, highest severity = medium | 400 | medium |
  | Threats found, highest severity = high | 200 | high |
  | Threats found, highest severity = critical | 50 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-94 Improper Control of Generation of Code
- **CVSS:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Confidence:** 75%

### 16.2 Hidden Iframe Detection

- **Check Weight:** 2.0
- **What it checks:** Iframes with 0 dimensions, `display:none`, `visibility:hidden`, or off-screen positioning. Also checks for iframes from suspicious TLDs (.ru, .cn, .tk, .ml, .ga, .cf, .top, .xyz, .buzz, .work).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No hidden/suspicious iframes | 1000 | info |
  | 1–2 threats | 250 | high |
  | 3+ threats | 50 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-829 Inclusion of Functionality from Untrusted Control Sphere
- **CVSS:** 8.8 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Confidence:** 80%

### 16.3 Cryptocurrency Miner Detection

- **Check Weight:** 2.0
- **What it checks:** Known crypto miner scripts (CoinHive, CryptoLoot, JSEcoin, DeepMiner, etc.) and WebSocket connections to mining pools.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No miners detected | 1000 | info |
  | Any miner detected | 0 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-506 Embedded Malicious Code
- **CVSS:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Confidence:** 90%

### 16.4 Suspicious Redirect Detection

- **Check Weight:** 1.5
- **What it checks:** Meta refresh redirects, JavaScript redirects to suspicious TLDs, window.open to suspicious domains.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No suspicious redirects | 1000 | info |
  | Any suspicious redirect detected | 100 | critical |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-601 URL Redirection to Untrusted Site
- **Confidence:** 70%

### 16.5 Malware Signature Detection

- **Check Weight:** 2.5
- **What it checks:** Known malware signatures: web shells (C99, R57, WSO, B374K), SEO spam (pharma), drive-by download indicators, obfuscated variable names (`_0x` pattern), hidden spam links.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No signatures | 1000 | info |
  | 1–2 signatures | 150 | high |
  | 3+ signatures | 0 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-506 Embedded Malicious Code
- **Confidence:** 65%

### 16.6 Malicious External Links

- **Check Weight:** 1.0
- **What it checks:** Links to suspicious TLDs (.tk, .ml, .ga, .cf, .gq), direct IP addresses, URL shorteners, and open redirect parameters.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No malicious links | 1000 | info |
  | 1–4 suspicious links | 500 | medium |
  | 5+ suspicious links | 100 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-829 Inclusion of Functionality from Untrusted Control Sphere
- **Confidence:** 60%
- **Remediation:** Scan website for injected malicious code. Remove unauthorized scripts and iframes. Change all admin passwords. Update CMS and plugins.

---

## 17. Threat Intelligence Scanner

**Category:** `threat_intel` | **Weight:** 8.0 | **Checks:** 4

Advanced threat detection including cryptojacking via WebWorkers/WASM, C2 server communication patterns, DNS blacklist checks, and domain reputation.

### 17.1 Cryptojacking Detection

- **Check Weight:** 2.5
- **What it checks:** WebWorker/WebAssembly mining indicators combined with mining-specific keywords (mine, hash, nonce, stratum, pool, monero, xmr, cryptonight), mining WebSocket connections, CPU throttle references.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No indicators | 1000 | info |
  | 1–2 indicators | 300 | high |
  | 3+ indicators | 0 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-506 Embedded Malicious Code
- **Confidence:** 90% (miners), 70% (contextual indicators)

### 17.2 C2 Server Communication

- **Check Weight:** 2.5
- **What it checks:** HTTP callbacks to direct IP addresses, Base64 data exfiltration, POST to IP addresses, WebSocket to IP addresses, dynamic script loading from IPs, known C2 framework indicators (Cobalt Strike, Meterpreter), data exfiltration patterns.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No indicators | 1000 | info |
  | 1–2 indicators | 200 | high |
  | 3+ indicators | 0 | critical |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-506 Embedded Malicious Code
- **Confidence:** 75%

### 17.3 Blacklist Check

- **Check Weight:** 2.0
- **What it checks:** Server IP against 8 DNS-based blacklists (Spamhaus ZEN, SpamCop, Barracuda, SORBS, CBL, UCEPROTECT, PSBL).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Not listed on any blacklist | 1000 | info |
  | Listed on 1–2 blacklists | 350 | high |
  | Listed on 3+ blacklists | 50 | critical |

- **OWASP:** A07:2021 Identification and Authentication Failures
- **CWE:** CWE-290 Authentication Bypass by Spoofing
- **Confidence:** 85%

### 17.4 Domain Reputation & Age

- **Check Weight:** 1.0
- **What it checks:** DNS health indicators (MX records, NS records, TXT records) and domain registration data via RDAP (registration date, registrar).
- **Scoring:** Base score 500, additive:

  | Indicator | Bonus |
  |-----------|:-----:|
  | Has MX records | +100 |
  | Has NS records | +50 |
  | Has TXT records | +50 |
  | Domain age >= 5 years | +250 |
  | Domain age 2–5 years | +150 |
  | Domain age 1–2 years | +50 |
  | Domain age < 1 year | +0 |

  Maximum: 1000

- **OWASP:** A07:2021 Identification and Authentication Failures
- **CWE:** CWE-290 Authentication Bypass by Spoofing
- **Confidence:** 70%
- **Remediation:** If blacklisted, investigate and resolve the cause (compromised server, spam). Request delisting from the relevant blacklist providers.

---

## 18. SEO & Technical Health Scanner

**Category:** `seo` | **Weight:** 7.0 | **Checks:** 6

Evaluates search engine optimization readiness and technical health indicators.

### 18.1 Meta Tags Quality

- **Check Weight:** 2.0
- **Scoring:** Additive (max 1000):
  - `<title>` present, 10–70 chars: +250
  - `<meta name="description">` present, 50–160 chars: +250
  - `<meta name="viewport">` present: +200
  - `<link rel="canonical">` present: +150
  - `<html lang="...">` present: +150

### 18.2 Open Graph Tags

- **Check Weight:** 1.5
- **Scoring:** Additive (max 1000):
  - `og:title`: +250
  - `og:description`: +250
  - `og:image`: +250
  - `og:url`: +125
  - `og:type`: +125

### 18.3 Sitemap Accessibility

- **Check Weight:** 1.5
- **Checks:** `/sitemap.xml` and `/sitemap_index.xml`
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Valid XML sitemap found | 1000 |
  | Sitemap found, redirect | 700 |
  | Sitemap found, not XML | 600 |
  | No sitemap found | 200 |

### 18.4 Robots.txt Quality

- **Check Weight:** 1.0
- **Scoring:** Additive (max 1000):
  - Has Sitemap directive: +400
  - Has specific Allow/Disallow rules: +300
  - Not blocking important paths (/, /css, /js): +300
  - Empty/minimal (< 3 non-empty lines): 500

### 18.5 Structured Data

- **Check Weight:** 0.5
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | JSON-LD found | 1000 |
  | Microdata (itemscope) found | 600 |
  | No structured data | 200 |

### 18.6 Mobile Friendliness

- **Check Weight:** 0.5
- **Scoring:** Additive (max 1000):
  - Viewport with `width=device-width`: +500
  - No fixed viewport width: +250
  - No fixed inline pixel widths (>= 4 digits): +250

- **Confidence:** 85–100%
- **Remediation:** Add proper meta tags, Open Graph tags, sitemap.xml, and structured data. Ensure mobile-responsive design.

---

## 19. Third-Party Scripts Risk Scanner

**Category:** `third_party` | **Weight:** 6.0 | **Checks:** 4

Evaluates the risk of external JavaScript and CSS dependencies.

### 19.1 External Script Count

- **Check Weight:** 2.0
- **Scoring:**

  | Count | Score |
  |------:|:-----:|
  | <= 3 | 1000 |
  | 4–6 | 850 |
  | 7–10 | 700 |
  | 11–15 | 500 |
  | 16–20 | 300 |
  | > 20 | 150 |

### 19.2 Subresource Integrity (SRI)

- **Check Weight:** 2.0
- **What it checks:** Percentage of external scripts with `integrity="sha..."` attributes.
- **Scoring:**

  | SRI Coverage | Score |
  |-------------:|:-----:|
  | No external scripts | 1000 |
  | 100% | 1000 |
  | >= 75% | 800 |
  | >= 50% | 600 |
  | > 0% | 400 |
  | 0% | 150 |

- **OWASP:** A08:2021 Software and Data Integrity Failures
- **CWE:** CWE-353 Missing Support for Integrity Check

### 19.3 Trusted Sources

- **Check Weight:** 1.0
- **What it checks:** Percentage of external scripts from known trusted CDNs (googleapis.com, cloudflare.com, jsdelivr.net, etc.) and presence of scripts from suspicious TLDs (.tk, .ml, .ga, .cf, .xyz, .top).
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Suspicious TLD detected | 50 |
  | 100% trusted | 1000 |
  | >= 80% trusted | 800 |
  | >= 60% trusted | 600 |
  | < 60% trusted | 300 |

### 19.4 External CSS Count

- **Check Weight:** 1.0
- **Scoring:**

  | Count | Score |
  |------:|:-----:|
  | <= 3 | 1000 |
  | 4–6 | 800 |
  | 7–10 | 600 |
  | > 10 | 400 |

- **OWASP:** A08:2021 Software and Data Integrity Failures
- **CWE:** CWE-829 Inclusion of Functionality from Untrusted Control Sphere
- **Confidence:** 80–100%
- **Remediation:** Add SRI hashes to all external scripts. Minimize the number of external dependencies. Only load scripts from trusted CDNs.

---

## 20. JavaScript Library Scanner

**Category:** `js_libraries` | **Weight:** 6.0 | **Checks:** 3

Detects outdated and vulnerable JavaScript libraries in the page source.

### 20.1 Outdated jQuery Detection

- **Check Weight:** 3.0
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | jQuery not detected | 1000 |
  | jQuery >= 3.7.x (latest) | 1000 |
  | jQuery 3.5.x–3.6.x (XSS fix present) | 850 |
  | jQuery 3.0.x–3.4.x (missing XSS fix) | 650 |
  | jQuery 2.x | 400 |
  | jQuery 1.12.x+ | 250 |
  | jQuery < 1.12 | 50 |

- **OWASP:** A06:2021 Vulnerable and Outdated Components
- **CWE:** CWE-1104 Use of Unmaintained Third Party Components
- **Confidence:** 85%

### 20.2 Known Vulnerable Libraries

- **Check Weight:** 2.0
- **What it detects:** AngularJS 1.x (XSS), Bootstrap < 3.4.1 / < 4.3.1 (XSS in tooltip/popover), Lodash < 4.17.21 (prototype pollution), Moment.js (any version, deprecated, ReDoS), Vue.js < 2.5.0 (XSS), React < 16.4.0 (XSS).
- **Scoring:**

  | Count | Score |
  |------:|:-----:|
  | 0 | 1000 |
  | 1 | 500 |
  | 2 | 300 |
  | 3+ | 100 |

- **OWASP:** A06:2021 Vulnerable and Outdated Components
- **CWE:** CWE-1104 Use of Unmaintained Third Party Components
- **Confidence:** 75%

### 20.3 Inline Script Analysis

- **Check Weight:** 1.0
- **What it checks:** Number of inline scripts and presence of dangerous patterns (`eval()`, `document.write()`, `innerHTML`).
- **Scoring:** Base score by count (<=3: 1000, <=10: 800, >10: 600), then penalties:
  - `eval()`: -200
  - `document.write()`: -150
  - `innerHTML`: -100
  - Minimum score: 100

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 XSS
- **Confidence:** 70%
- **Remediation:** Update all JavaScript libraries to the latest versions. Replace deprecated libraries (Moment.js with Day.js or Luxon). Remove unsafe inline script patterns.

---

## 21. WordPress Security Scanner

**Category:** `wordpress` | **Weight:** 8.0 | **Checks:** 6 (1 if not WordPress)

Specialized scanner for WordPress installations. If WordPress is not detected, only the version check runs (score 1000).

### 21.1 WordPress Version

- **Check Weight:** 2.0
- **How it detects:** Meta generator tag, wp-embed.min.js version, /feed/ generator tag, and common WP patterns in page source.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Not WordPress | 1000 |
  | WP >= 6.8 (latest) | 1000 |
  | WP 6.7 | 800 |
  | WP 6.6 | 600 |
  | WP 6.0–6.5 | 400 |
  | WP < 6.0 | 100 |
  | Version unknown | 600 |

- **OWASP:** A06:2021 Vulnerable and Outdated Components
- **CWE:** CWE-1104 Use of Unmaintained Third Party Components

### 21.2 WP Login Page Exposure

- **Check Weight:** 1.5
- **What it checks:** Accessibility of `/wp-login.php` and whether it shows the standard WordPress login form.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Not accessible (404/403/410) | 1000 |
  | Standard WP login form visible | 300 |
  | Custom login form (not standard WP) | 700 |
  | Connection error | 1000 |

- **OWASP:** A07:2021 Identification and Authentication Failures
- **CWE:** CWE-307 Improper Restriction of Excessive Authentication Attempts

### 21.3 WP XML-RPC Exposure

- **Check Weight:** 1.5
- **What it checks:** Whether `/xmlrpc.php` responds to `system.listMethods` XML-RPC call.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | Not accessible (403/404/405) | 1000 | info |
  | Fully open (lists methods) | 100 | critical |
  | Responds but restricted | 700 | — |
  | Connection error or other status | 1000 | info |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-749 Exposed Dangerous Method or Function

### 21.4 WP REST API User Enumeration

- **Check Weight:** 1.0
- **What it checks:** Whether `/wp-json/wp/v2/users` exposes user information.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Blocked (403/404/401) | 1000 |
  | Returns empty data | 800 |
  | Exposes user data | 200 |

- **OWASP:** A01:2021 Broken Access Control
- **CWE:** CWE-200 Exposure of Sensitive Information

### 21.5 WP Readme/License Exposure

- **Check Weight:** 1.0
- **What it checks:** Accessibility of `/readme.html` and `/license.txt`.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | Neither accessible | 1000 |
  | One accessible | 600 |
  | Both accessible | 300 |

### 21.6 WP Debug Mode

- **Check Weight:** 1.0
- **What it checks:** Accessibility of `/wp-content/debug.log` and PHP notices/warnings in page source.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No debug indicators | 1000 | info |
  | PHP notices in source (WP_DEBUG likely on) | 400 | — |
  | debug.log publicly accessible | 50 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-209 Error Message Containing Sensitive Information
- **Remediation:** Hide or rename wp-login.php. Disable XML-RPC. Block REST API user enumeration. Remove readme.html and license.txt. Set `WP_DEBUG` to `false` in production.

---

## 22. XSS Vulnerability Scanner

**Category:** `xss` | **Weight:** 9.0 | **Checks:** 5

Detects Cross-Site Scripting vulnerabilities using safe, non-destructive canary-based reflection analysis. The scanner never injects actual malicious payloads -- only harmless marker strings.

### 22.1 Reflected XSS Detection

- **Check Weight:** 3.0
- **What it checks:** Extracts forms and their input fields, injects a harmless canary string (`vscan7x7test`) into each parameter, then checks if/where the canary is reflected in the response.
- **Limits:** Max 5 forms, max 10 parameters total.
- **Scoring:**

  | Worst Reflection Context | Score |
  |--------------------------|:-----:|
  | No reflection (`none`) | 1000 |
  | Encoded reflection | 800 |
  | Body text reflection | 400 |
  | Script or attribute context | 100 |
  | Multiple unescaped reflections (>= 2) | 50 |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 XSS
- **CVSS:** 6.1 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Confidence:** 80%

### 22.2 DOM-Based XSS Indicators

- **Check Weight:** 2.0
- **What it checks:** Presence of dangerous DOM sink patterns in page source (excluding comments): `document.write()`, `.innerHTML =`, `eval()`, `location.href =`, `location.assign()`, `location.replace()`, `document.cookie =`, `.outerHTML =`, `setTimeout("...")`, `setInterval("...")`.
- **Scoring:**

  | Sink Count | Score |
  |-----------:|:-----:|
  | 0 | 1000 |
  | 1–2 | 750 |
  | 3–5 | 500 |
  | 6–10 | 300 |
  | > 10 | 100 |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 XSS
- **Confidence:** 70%

### 22.3 Input Sanitization Check

- **Check Weight:** 2.0
- **What it checks:** Sends 3 test payloads to the homepage via `?q=` parameter and checks whether they are blocked, escaped, or reflected unescaped:
  1. `<script>alert(1)</script>` (script injection)
  2. `"><img src=x onerror=alert(1)>` (event handler injection)
  3. `javascript:alert(1)` (JavaScript URI)
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | All blocked (403 or not in response) | 1000 |
  | Some escaped, none raw-reflected | 500 |
  | Event handler reflected unescaped | 150 |
  | Script tag reflected unescaped | 100 |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 XSS
- **Confidence:** 75%

### 22.4 Content-Type & X-XSS-Protection Headers

- **Check Weight:** 1.0
- **Scoring:** Additive (max 1000):
  - Content-Type includes `charset`: +500
  - `X-XSS-Protection: 1; mode=block`: +500
  - `X-XSS-Protection: 0` (explicitly disabled): +300
  - Other X-XSS-Protection value: +400
  - Missing X-XSS-Protection: +0

- **Confidence:** 100%

### 22.5 URL Parameter Reflection Analysis

- **Check Weight:** 1.0
- **What it checks:** Tests common query parameters (`q`, `search`, `query`, `s`, `id`) with the canary string and classifies reflection context.
- **Scoring:**

  | Worst Reflection Context | Score |
  |--------------------------|:-----:|
  | No reflection | 1000 |
  | Encoded | 900 |
  | Body text | 500 |
  | Attribute context | 300 |
  | Script context | 100 |

- **OWASP:** A03:2021 Injection
- **CWE:** CWE-79 XSS
- **Confidence:** 75%
- **Remediation:** Implement output encoding for all user input. Use CSP to prevent inline script execution. Add X-XSS-Protection header. Validate and sanitize all inputs server-side.

---

## 23. Secrets Detection Scanner

**Category:** `secrets` | **Weight:** 8.0 | **Checks:** 4

Scans page source for exposed API keys, private keys, database connection strings, and hardcoded passwords.

### 23.1 API Key Exposure

- **Check Weight:** 3.0
- **What it detects:** AWS Access Keys (`AKIA...`), Google API Keys (`AIza...`), Stripe Secret Keys (`sk_live_...`), GitHub PATs (`ghp_...`, `github_pat_...`), Slack Bot Tokens (`xoxb-...`), generic API key patterns.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No API keys | 1000 | info |
  | 1 API key found | 100 | critical |
  | 2+ API keys found | 0 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-798 Use of Hard-coded Credentials
- **CVSS:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Confidence:** 90%

### 23.2 Private Key Exposure

- **Check Weight:** 2.0
- **What it detects:** PEM-encoded private keys (`-----BEGIN [RSA|EC|DSA] PRIVATE KEY-----`) and certificates (`-----BEGIN CERTIFICATE-----`).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No private keys/certificates | 1000 | info |
  | Private key or certificate material found | 0 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-312 Cleartext Storage of Sensitive Information
- **CVSS:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Confidence:** 95%

### 23.3 Database Connection String Exposure

- **Check Weight:** 2.0
- **What it detects:** MySQL, PostgreSQL, MongoDB, Redis connection strings, JDBC URLs, and `DB_PASSWORD`/`DATABASE_URL` variables. Distinguishes between strings with and without embedded credentials.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No connection strings | 1000 | info |
  | Connection strings without credentials | 400 | medium |
  | Connection strings with credentials | 0 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-200 Exposure of Sensitive Information
- **CVSS:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Confidence:** 85%

### 23.4 Email/Password Exposure

- **Check Weight:** 1.0
- **What it detects:** Hardcoded `password = "..."` patterns, SMTP/mail password variables, environment variable patterns (`DB_PASSWORD`, `APP_KEY`, `SECRET_KEY`, `API_SECRET`).
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No passwords found | 1000 | info |
  | Hardcoded passwords found | 100 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-312 Cleartext Storage of Sensitive Information
- **Confidence:** 80%
- **Remediation:** Immediately rotate any exposed API keys. Remove secrets from source code. Use environment variables or secret management services. Ensure `.env` files are not accessible publicly.

---

## 24. Subdomain Discovery Scanner

**Category:** `subdomains` | **Weight:** 5.0 | **Checks:** 3

Enumerates common subdomains and checks for security issues including HTTPS coverage and subdomain takeover risks.

### 24.1 Common Subdomain Enumeration

- **Check Weight:** 2.0
- **What it checks:** DNS resolves 47 common subdomain prefixes (www, mail, ftp, admin, cpanel, webmail, remote, blog, shop, api, dev, staging, test, beta, portal, vpn, ns1, ns2, mx, smtp, pop, imap, login, cdn, media, static, assets, app, dashboard, db, sql, phpmyadmin, mysql, backup, old, new, demo, cms, intranet, extranet, wiki, docs, support, help, status, monitor).
- **Scoring:**

  | Count | Score | Severity |
  |------:|:-----:|----------|
  | <= 5 | 1000 | info |
  | 6–15 | 800 | low |
  | 16–30 | 600 | medium |
  | > 30 | 400 | medium |

- **Confidence:** 70%

### 24.2 Subdomain Security Check

- **Check Weight:** 2.0
- **What it checks:** HTTPS support ratio across discovered subdomains (checks up to 10).
- **Scoring:**

  | HTTPS Ratio | Score |
  |------------:|:-----:|
  | 100% | 1000 |
  | >= 80% | 800 |
  | >= 50% | 600 |
  | < 50% | 300 |

- **Confidence:** 90%

### 24.3 Dangling DNS / Subdomain Takeover Risk

- **Check Weight:** 1.0
- **What it checks:** CNAMEs pointing to known takeover-vulnerable services (github.io, herokuapp.com, s3.amazonaws.com, azurewebsites.net, cloudfront.net, shopify.com, ghost.io, pantheon.io, zendesk.com, surge.sh, bitbucket.io, wordpress.com, tumblr.com, flywheel.com) that return 404.
- **Scoring:**

  | Condition | Score | Severity |
  |-----------|:-----:|----------|
  | No dangerous CNAMEs | 1000 | info |
  | CNAMEs to external services, all responding correctly | 800 | low |
  | Potential takeover detected (CNAME + 404) | 100 | critical |

- **OWASP:** A05:2021 Security Misconfiguration
- **CWE:** CWE-16 Configuration
- **CVSS:** 8.6 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`
- **Confidence:** 75%
- **Remediation:** Remove DNS records for decommissioned services. Ensure all subdomains use HTTPS. Monitor for subdomain takeover risks regularly.

---

## 25. Technology Detection Scanner

**Category:** `tech_stack` | **Weight:** 4.0 | **Checks:** 3

Identifies web frameworks, server technologies, and JavaScript libraries in use. Primarily informational.

### 25.1 Web Framework Detection

- **Check Weight:** 1.5
- **What it detects:** WordPress, Drupal, Joomla, Laravel, Django, Express, ASP.NET, Ruby on Rails, Next.js, Nuxt.js, React, Vue.js, Angular, Svelte, Moodle, Elementor — via body pattern matching and HTTP headers.
- **Scoring:** Always 1000 (informational — detection itself is not a security issue).
- **Confidence:** 85%

### 25.2 Server Technology Detection

- **Check Weight:** 1.5
- **What it detects:** Server software (Apache, Nginx, LiteSpeed, IIS, Cloudflare, etc.), runtime via X-Powered-By (PHP, ASP.NET, Node.js, Ruby), CDNs (Cloudflare, CloudFront, Akamai, Fastly), and X-Generator header.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | No technologies detected | 1000 |
  | Technologies detected, no version exposed | 1000 |
  | Technologies detected with version exposed | 700 |

- **Confidence:** 85%

### 25.3 JavaScript Library Inventory

- **Check Weight:** 1.0
- **What it detects:** jQuery, React, Vue.js, Angular, Lodash, Moment.js, Bootstrap, Tailwind CSS — with version extraction and outdated detection.
- **Scoring:**

  | Condition | Score |
  |-----------|:-----:|
  | No libraries or all up to date | 1000 |
  | Libraries found with outdated versions | 600 |

- **Confidence:** 85%
- **Remediation:** Remove version-revealing headers. Update outdated libraries. This scanner is primarily for visibility and does not penalize technology detection itself.

---

## OWASP Top 10 2021 Coverage Matrix

| OWASP ID | Name | Scanners Covering |
|----------|------|-------------------|
| **A01:2021** | Broken Access Control | Headers (X-Frame-Options, Referrer-Policy, Permissions-Policy), Cookies, CORS, Directory (Git, Admin Panel), WordPress (REST API), Malware (Suspicious Redirects), Advanced Security (COEP, COOP, CORP) |
| **A02:2021** | Cryptographic Failures | SSL/TLS (all 4 checks), DNS (CAA), Mixed Content (all 3 checks), Advanced Security (OCSP Stapling) |
| **A03:2021** | Injection | Headers (CSP, X-XSS-Protection), JS Libraries (Inline Scripts), Malware (Malicious JS, Hidden Iframes, Crypto Miners, Malware Signatures, External Links), Threat Intel (Cryptojacking, C2), XSS (all 5 checks) |
| **A04:2021** | Insecure Design | DDoS (Rate Limiting) |
| **A05:2021** | Security Misconfiguration | Headers (HSTS, X-Content-Type-Options), Server Info (all 3), Directory (all 9), Performance (all 3), DDoS (CDN, WAF), HTTP Methods (both), Info Disclosure (all 3), WordPress (XML-RPC, Readme, Debug), Secrets (all 4), Subdomains (all 3) |
| **A06:2021** | Vulnerable and Outdated Components | JS Libraries (jQuery, Vulnerable Libraries), WordPress (Version) |
| **A07:2021** | Identification and Authentication Failures | DNS (SPF, DMARC), Threat Intel (Blacklist, Domain Age), WordPress (Login Page) |
| **A08:2021** | Software and Data Integrity Failures | Third-Party Scripts (all 4 checks) |
| **A09:2021** | Security Logging and Monitoring Failures | Not directly covered (infrastructure-level concern) |
| **A10:2021** | Server-Side Request Forgery (SSRF) | Not directly covered (requires application-specific testing) |

---

## CWE Coverage List

| CWE ID | Name | Check(s) |
|--------|------|----------|
| CWE-16 | Configuration | X-Content-Type-Options, Hosting checks, Subdomains, Cache/Page/Compression |
| CWE-79 | XSS | CSP, X-XSS-Protection, XSS Scanner (all 5), Inline Scripts |
| CWE-94 | Code Injection | Malicious JavaScript Detection |
| CWE-200 | Exposure of Sensitive Information | Server Header, X-Powered-By, CMS Detection, Version Disclosure, WP REST API, WP Readme, DB Connection Strings, Server Technology |
| CWE-209 | Error Message Containing Sensitive Information | Error Page Info Disclosure, WP Debug Mode |
| CWE-250 | Execution with Unnecessary Privileges | Permissions-Policy |
| CWE-290 | Authentication Bypass by Spoofing | SPF, DMARC, Blacklist, Domain Age |
| CWE-295 | Improper Certificate Validation | Certificate Validity, CAA Record |
| CWE-299 | Improper Check for Certificate Revocation | OCSP Stapling |
| CWE-307 | Improper Restriction of Excessive Auth Attempts | WP Login Page |
| CWE-312 | Cleartext Storage of Sensitive Information | Private Key Exposure, Email/Password Exposure |
| CWE-319 | Cleartext Transmission | HTTPS Enabled, HTTPS Redirect, Mixed Content (all 3) |
| CWE-326 | Inadequate Encryption Strength | TLS Version |
| CWE-346 | Origin Validation Error | COEP, COOP, CORP |
| CWE-353 | Missing Support for Integrity Check | Subresource Integrity (SRI) |
| CWE-400 | Uncontrolled Resource Consumption | Response Time, TTFB, TLS Handshake |
| CWE-425 | Direct Request (Forced Browsing) | Admin Panel Exposure |
| CWE-506 | Embedded Malicious Code | Crypto Miners, Malware Signatures, Cryptojacking, C2 Communication |
| CWE-523 | Unprotected Transport of Credentials | HSTS |
| CWE-538 | Sensitive Info in Externally-Accessible File | Robots.txt, .env, .git, phpinfo, Backup, .htaccess, WP Config Backup, Server Status |
| CWE-601 | Open Redirect | Suspicious Redirect Detection |
| CWE-614 | Sensitive Cookie Without Secure Attribute | Cookie Security |
| CWE-615 | Sensitive Information in Comments | Sensitive HTML Comments |
| CWE-693 | Protection Mechanism Failure | WAF |
| CWE-749 | Exposed Dangerous Method or Function | HTTP Methods, OPTIONS Disclosure, WP XML-RPC |
| CWE-770 | Resource Allocation Without Limits | CDN/DDoS Protection, Rate Limiting |
| CWE-798 | Use of Hard-coded Credentials | API Key Exposure |
| CWE-829 | Inclusion from Untrusted Control Sphere | Hidden Iframes, External Links, External Scripts, Trusted Sources, External CSS |
| CWE-942 | Permissive Cross-domain Policy | CORS Wildcard Origin, CORS Credentials |
| CWE-1021 | Clickjacking | X-Frame-Options |
| CWE-1104 | Use of Unmaintained Third Party Components | jQuery, Vulnerable Libraries, WordPress Version |

---

## CVSS Distribution

Distribution of CVSS v3.1 base scores across all mapped checks:

```
Critical (9.0-10.0)  ████████  8 checks
  9.8: API Key Exposure, Private Key Exposure, DB Connection Strings,
       Malicious JavaScript Detection

High (7.0-8.9)       ██████████  10 checks
  8.8: Hidden Iframe Detection
  8.6: Subdomain Takeover
  7.5: HTTPS Enabled, TLS Version, CORS Wildcard, Environment File,
       Git Repository, XML-RPC, Crypto Miner, Debug Mode

Medium (4.0-6.9)     ██████████████  14 checks
  6.1: HSTS, CSP, X-Frame-Options, Reflected XSS, DOM-Based XSS,
       Input Sanitization
  5.3: Certificate Validity, HTTPS Redirect, SPF, DMARC, Admin Panel,
       HTTP Methods, REST API User Enum
  4.3: Permissions-Policy

Low (0.1-3.9)        0 checks

Informational        ████████████████████  20+ checks
  Performance, Hosting, Content, SEO, Technology Detection
```

---

## Scan Policy Descriptions (Detailed)

### Light Scan
- **Categories (8):** ssl, headers, cookies, mixed_content, performance, dns, seo, content
- **Timeout:** 30 seconds per target
- **Best for:** Quick health check, regular monitoring, initial assessment
- **Estimated checks:** ~35

### Standard Scan
- **Categories (16):** All Light + server_info, directory, ddos, cors, http_methods, info_disclosure, hosting, secrets
- **Timeout:** 60 seconds per target
- **Best for:** Comprehensive security audit, compliance checking
- **Estimated checks:** ~65

### Deep Scan
- **Categories (25):** All Standard + advanced_security, malware, threat_intel, third_party, js_libraries, wordpress, xss, subdomains, tech_stack
- **Timeout:** 120 seconds per target
- **Best for:** Full security assessment, penetration test preparation, incident response
- **Estimated checks:** ~100+

---

*This document was generated from the VScan-MOHESR source code and represents the exact scoring logic implemented in the scanner engine.*
