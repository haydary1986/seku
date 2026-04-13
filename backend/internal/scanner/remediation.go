package scanner

// RemediationGuide provides step-by-step fix instructions for a specific security check.
type RemediationGuide struct {
	CheckName    string            `json:"check_name"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Priority     string            `json:"priority"`      // critical, high, medium, low
	TimeEstimate string            `json:"time_estimate"` // "5 minutes", "30 minutes"
	Guides       map[string]string `json:"guides"`        // key: server type, value: markdown steps
}

// RemediationDB maps check names to their remediation guides.
var RemediationDB = map[string]RemediationGuide{}

func init() {
	populateRemediationDB()
}

func populateRemediationDB() {
	// -------------------------------------------------------------------------
	// 1. HSTS
	// -------------------------------------------------------------------------
	RemediationDB["HSTS"] = RemediationGuide{
		CheckName:    "HSTS",
		Title:        "Enable HTTP Strict Transport Security (HSTS)",
		Description:  "HSTS forces browsers to only connect via HTTPS, preventing downgrade attacks and cookie hijacking.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable HSTS

1. Log in to your **Cloudflare dashboard**
2. Select your domain
3. Go to **SSL/TLS** > **Edge Certificates**
4. Scroll to **HTTP Strict Transport Security (HSTS)**
5. Click **Enable HSTS**
6. Configure:
   - **Max-Age**: 12 months (recommended)
   - **Include subdomains**: Yes
   - **Preload**: Yes
   - **No-Sniff**: Yes
7. Click **Save**

> Cloudflare will add the header automatically to all responses.`,

			"apache": `## Apache - Enable HSTS

Add to your ` + "`" + `.htaccess` + "`" + ` or virtual host configuration:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

Make sure ` + "`" + `mod_headers` + "`" + ` is enabled:

` + "```bash" + `
sudo a2enmod headers
sudo systemctl restart apache2
` + "```",

			"nginx": `## Nginx - Enable HSTS

Add inside your ` + "`" + `server` + "`" + ` block (HTTPS only):

` + "```nginx" + `
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
` + "```" + `

Then reload:

` + "```bash" + `
sudo nginx -t && sudo systemctl reload nginx
` + "```" + `

> Only add this to HTTPS server blocks, not HTTP.`,

			"litespeed": `## LiteSpeed - Enable HSTS

**Option 1: Via .htaccess**

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

**Option 2: Via LiteSpeed Web Admin**

1. Go to **Configuration** > **Virtual Hosts** > your host > **Context**
2. Add a **Static Context** for ` + "`" + `/` + "`" + `
3. Under **Header Operations**, add:
   ` + "`" + `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` + "`" + `
4. Restart LiteSpeed`,

			"plesk": `## Plesk - Enable HSTS

1. Log in to **Plesk**
2. Go to **Domains** > select your domain
3. Click **Apache & nginx Settings**
4. In **Additional Apache directives**, add:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

5. Click **OK** / **Apply**`,

			"cpanel": `## cPanel - Enable HSTS

**Option 1: Via .htaccess**

1. Open **File Manager** in cPanel
2. Navigate to your document root
3. Edit ` + "`" + `.htaccess` + "`" + `
4. Add:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

**Option 2: Via cPanel UI (if available)**

1. Go to **Security** > **HTTP Strict Transport Security**
2. Enable for your domain with max-age 12 months`,

			"wordpress": `## WordPress - Enable HSTS

**Option 1: Plugin (Recommended)**

Install and activate **HTTP Headers** or **Really Simple SSL Pro** plugin:
1. Go to **Plugins** > **Add New**
2. Search for "HTTP Headers" or "Really Simple SSL"
3. Activate and configure HSTS settings

**Option 2: Via wp-config.php (advanced)**

Add to your theme's ` + "`" + `functions.php` + "`" + ` or a custom plugin:

` + "```php" + `
add_action('send_headers', function() {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 2. Content Security Policy
	// -------------------------------------------------------------------------
	RemediationDB["Content Security Policy"] = RemediationGuide{
		CheckName:    "Content Security Policy",
		Title:        "Configure Content Security Policy (CSP)",
		Description:  "CSP prevents XSS attacks by controlling which resources the browser is allowed to load.",
		Priority:     "high",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add CSP Header

**Option 1: Transform Rules**

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Click **Create rule**
3. Set:
   - **Header name**: ` + "`" + `Content-Security-Policy` + "`" + `
   - **Value**: ` + "`" + `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';` + "`" + `
4. Deploy

**Option 2: Cloudflare Workers**

Create a Worker that adds the CSP header to responses.`,

			"apache": `## Apache - Add CSP Header

Add to ` + "`" + `.htaccess` + "`" + ` or virtual host:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```" + `

> **Tip**: Start with ` + "`" + `Content-Security-Policy-Report-Only` + "`" + ` to test without breaking anything.`,

			"nginx": `## Nginx - Add CSP Header

Add inside your ` + "`" + `server` + "`" + ` block:

` + "```nginx" + `
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
` + "```" + `

Then reload:

` + "```bash" + `
sudo nginx -t && sudo systemctl reload nginx
` + "```",

			"litespeed": `## LiteSpeed - Add CSP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```",

			"plesk": `## Plesk - Add CSP Header

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. In **Additional Apache directives**:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```",

			"cpanel": `## cPanel - Add CSP Header

Edit ` + "`" + `.htaccess` + "`" + ` in your document root:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Add CSP Header

**Option 1: Plugin**

Install **HTTP Headers** or **WP Content Security Policy** plugin.

**Option 2: functions.php**

` + "```php" + `
add_action('send_headers', function() {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
});
` + "```" + `

> WordPress often requires ` + "`" + `'unsafe-inline'` + "`" + ` for scripts/styles due to inline code in themes and plugins.`,
		},
	}

	// -------------------------------------------------------------------------
	// 3. X-Frame-Options
	// -------------------------------------------------------------------------
	RemediationDB["X-Frame-Options"] = RemediationGuide{
		CheckName:    "X-Frame-Options",
		Title:        "Set X-Frame-Options Header",
		Description:  "Prevents your site from being embedded in iframes, protecting against clickjacking attacks.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - X-Frame-Options

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add header:
   - **Name**: ` + "`" + `X-Frame-Options` + "`" + `
   - **Value**: ` + "`" + `DENY` + "`" + ` (or ` + "`" + `SAMEORIGIN` + "`" + ` if you embed your own pages)`,

			"apache": `## Apache - X-Frame-Options

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
` + "```",

			"nginx": `## Nginx - X-Frame-Options

` + "```nginx" + `
add_header X-Frame-Options "DENY" always;
` + "```",

			"litespeed": `## LiteSpeed - X-Frame-Options

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
` + "```",

			"plesk": `## Plesk - X-Frame-Options

In **Apache & nginx Settings** > **Additional Apache directives**:

` + "```apache" + `
Header always set X-Frame-Options "DENY"
` + "```",

			"cpanel": `## cPanel - X-Frame-Options

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
` + "```",

			"wordpress": `## WordPress - X-Frame-Options

WordPress sends ` + "`" + `X-Frame-Options: SAMEORIGIN` + "`" + ` by default for admin pages. To set it site-wide:

` + "```php" + `
add_action('send_headers', function() {
    header('X-Frame-Options: DENY');
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 4. Permissions-Policy
	// -------------------------------------------------------------------------
	RemediationDB["Permissions-Policy"] = RemediationGuide{
		CheckName:    "Permissions-Policy",
		Title:        "Configure Permissions-Policy Header",
		Description:  "Controls which browser features (camera, microphone, geolocation, etc.) your site can use.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Permissions-Policy

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add:
   - **Name**: ` + "`" + `Permissions-Policy` + "`" + `
   - **Value**: ` + "`" + `camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()` + "`",

			"apache": `## Apache - Permissions-Policy

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
</IfModule>
` + "```",

			"nginx": `## Nginx - Permissions-Policy

` + "```nginx" + `
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;
` + "```",

			"litespeed": `## LiteSpeed - Permissions-Policy

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
</IfModule>
` + "```",

			"plesk": `## Plesk - Permissions-Policy

In **Apache & nginx Settings**:

` + "```apache" + `
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
` + "```",

			"cpanel": `## cPanel - Permissions-Policy

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Permissions-Policy

` + "```php" + `
add_action('send_headers', function() {
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()');
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 5. HTTPS Redirect
	// -------------------------------------------------------------------------
	RemediationDB["HTTP to HTTPS Redirect"] = RemediationGuide{
		CheckName:    "HTTP to HTTPS Redirect",
		Title:        "Force HTTPS Redirect",
		Description:  "Ensures all HTTP traffic is automatically redirected to HTTPS for encrypted connections.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Force HTTPS

1. Go to **SSL/TLS** > **Edge Certificates**
2. Enable **Always Use HTTPS**
3. Optionally enable **Automatic HTTPS Rewrites** under SSL/TLS settings`,

			"apache": `## Apache - Force HTTPS

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
` + "```" + `

Or in the virtual host:

` + "```apache" + `
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>
` + "```",

			"nginx": `## Nginx - Force HTTPS

` + "```nginx" + `
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
` + "```",

			"litespeed": `## LiteSpeed - Force HTTPS

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
` + "```",

			"plesk": `## Plesk - Force HTTPS

1. Go to **Domains** > your domain > **Hosting Settings**
2. Check **Permanent SEO-safe 301 redirect from HTTP to HTTPS**
3. Click **OK**`,

			"cpanel": `## cPanel - Force HTTPS

1. Go to **Domains** > **Redirects**
2. Or edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
` + "```",

			"wordpress": `## WordPress - Force HTTPS

1. Go to **Settings** > **General**
2. Change both URLs to ` + "`" + `https://` + "`" + `
3. Install **Really Simple SSL** plugin for automatic fixing
4. Add to ` + "`" + `wp-config.php` + "`" + `:

` + "```php" + `
define('FORCE_SSL_ADMIN', true);
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 6. TLS Version
	// -------------------------------------------------------------------------
	RemediationDB["TLS Version"] = RemediationGuide{
		CheckName:    "TLS Version",
		Title:        "Set Minimum TLS 1.2",
		Description:  "Disable old TLS versions (1.0, 1.1) that have known vulnerabilities.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Minimum TLS Version

1. Go to **SSL/TLS** > **Edge Certificates**
2. Find **Minimum TLS Version**
3. Set to **TLS 1.2** (recommended)`,

			"apache": `## Apache - Minimum TLS 1.2

` + "```apache" + `
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on
` + "```" + `

Restart Apache after changes.`,

			"nginx": `## Nginx - Minimum TLS 1.2

` + "```nginx" + `
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;
` + "```" + `

` + "```bash" + `
sudo nginx -t && sudo systemctl reload nginx
` + "```",

			"litespeed": `## LiteSpeed - Minimum TLS 1.2

1. In **LiteSpeed Web Admin** > **Listeners** > your listener
2. Set **SSL Protocol Version**: TLSv1.2 TLSv1.3
3. Restart LiteSpeed`,

			"plesk": `## Plesk - Minimum TLS 1.2

1. Go to **Tools & Settings** > **SSL/TLS Certificates**
2. Under **Apache SSL settings**, disable TLS 1.0 and 1.1
3. Or edit Apache/Nginx configuration directly`,

			"cpanel": `## cPanel - Minimum TLS 1.2

1. Log in to **WHM** (root access required)
2. Go to **Service Configuration** > **Apache Configuration** > **Global Configuration**
3. Set **SSL/TLS Protocols**: TLSv1.2 TLSv1.3
4. Rebuild Apache configuration`,
		},
	}

	// -------------------------------------------------------------------------
	// 7. HTTP Methods
	// -------------------------------------------------------------------------
	RemediationDB["Dangerous Methods"] = RemediationGuide{
		CheckName:    "Dangerous Methods",
		Title:        "Block Dangerous HTTP Methods",
		Description:  "Disable TRACE, DELETE, PUT, and other dangerous HTTP methods that could be exploited.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block HTTP Methods

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.method in {"TRACE" "DELETE" "PUT" "PATCH" "OPTIONS"})` + "`" + `
   - **Action**: Block`,

			"apache": `## Apache - Block Dangerous Methods

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
` + "```" + `

To specifically disable TRACE:

` + "```apache" + `
TraceEnable Off
` + "```",

			"nginx": `## Nginx - Block Dangerous Methods

` + "```nginx" + `
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}
` + "```",

			"litespeed": `## LiteSpeed - Block Dangerous Methods

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|DELETE|TRACK|PUT) [NC]
RewriteRule .* - [F]
` + "```",

			"plesk": `## Plesk - Block Dangerous Methods

In **Apache & nginx Settings** > **Additional Apache directives**:

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
TraceEnable Off
` + "```",

			"cpanel": `## cPanel - Block Dangerous Methods

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|DELETE|TRACK|PUT) [NC]
RewriteRule .* - [F]
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 8. DMARC
	// -------------------------------------------------------------------------
	RemediationDB["DMARC Record"] = RemediationGuide{
		CheckName:    "DMARC Record",
		Title:        "Configure DMARC DNS Record",
		Description:  "DMARC prevents email spoofing by telling receivers how to handle unauthenticated emails from your domain.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add DMARC Record

1. Go to **DNS** > **Records**
2. Click **Add record**
3. Set:
   - **Type**: TXT
   - **Name**: ` + "`" + `_dmarc` + "`" + `
   - **Content**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1; adkim=s; aspf=s` + "`" + `

**Progressive rollout recommended:**
- Start with ` + "`" + `p=none` + "`" + ` (monitor only)
- Move to ` + "`" + `p=quarantine` + "`" + ` after reviewing reports
- Finally set ` + "`" + `p=reject` + "`" + ` for full protection`,

			"apache": `## DNS Provider - Add DMARC Record

DMARC is a **DNS record**, not a server configuration. Add this TXT record at your DNS provider:

- **Host**: ` + "`" + `_dmarc` + "`" + `
- **Type**: TXT
- **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"nginx": `## DNS Provider - Add DMARC Record

DMARC is a **DNS record**. Add this TXT record:

- **Host**: ` + "`" + `_dmarc` + "`" + `
- **Type**: TXT
- **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"litespeed": `## DNS Provider - Add DMARC Record

Add a TXT record at your DNS provider:

- **Host**: ` + "`" + `_dmarc` + "`" + `
- **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"plesk": `## Plesk - Add DMARC Record

1. Go to **Domains** > your domain > **DNS Settings**
2. Add a TXT record:
   - **Host**: ` + "`" + `_dmarc` + "`" + `
   - **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"cpanel": `## cPanel - Add DMARC Record

1. Go to **Zone Editor** or **Advanced DNS Zone Editor**
2. Add a TXT record:
   - **Name**: ` + "`" + `_dmarc.yourdomain.com` + "`" + `
   - **Type**: TXT
   - **Record**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",
		},
	}

	// -------------------------------------------------------------------------
	// 9. SPF
	// -------------------------------------------------------------------------
	RemediationDB["SPF Record"] = RemediationGuide{
		CheckName:    "SPF Record",
		Title:        "Configure SPF DNS Record",
		Description:  "SPF specifies which mail servers are authorized to send email on behalf of your domain.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add SPF Record

1. Go to **DNS** > **Records**
2. Add a TXT record:
   - **Name**: ` + "`" + `@` + "`" + `
   - **Content**: ` + "`" + `v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all` + "`" + `

Adjust ` + "`" + `include:` + "`" + ` entries based on your email provider:
- **Google Workspace**: ` + "`" + `include:_spf.google.com` + "`" + `
- **Microsoft 365**: ` + "`" + `include:spf.protection.outlook.com` + "`" + `
- **No email**: ` + "`" + `v=spf1 -all` + "`" + ``,

			"apache": `## DNS Provider - Add SPF Record

Add a TXT record at your DNS provider:

- **Host**: ` + "`" + `@` + "`" + ` (root domain)
- **Type**: TXT
- **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`" + `

Adjust based on your mail provider.`,

			"nginx": `## DNS Provider - Add SPF Record

SPF is a DNS record. Add at your DNS provider:

- **Type**: TXT
- **Host**: ` + "`" + `@` + "`" + `
- **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",

			"litespeed": `## DNS Provider - Add SPF Record

Add at your DNS provider:

- **Type**: TXT
- **Host**: ` + "`" + `@` + "`" + `
- **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",

			"plesk": `## Plesk - Add SPF Record

1. Go to **Domains** > your domain > **DNS Settings**
2. Add a TXT record:
   - **Host**: (leave blank for root)
   - **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",

			"cpanel": `## cPanel - Add SPF Record

1. Go to **Email** > **Email Deliverability**
2. Or manually via **Zone Editor**:
   - **Name**: ` + "`" + `yourdomain.com` + "`" + `
   - **Type**: TXT
   - **Record**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",
		},
	}

	// -------------------------------------------------------------------------
	// 10. Mixed Content
	// -------------------------------------------------------------------------
	RemediationDB["Mixed Content Check"] = RemediationGuide{
		CheckName:    "Mixed Content Check",
		Title:        "Fix Mixed Content Issues",
		Description:  "Mixed content occurs when HTTPS pages load resources over HTTP, weakening security.",
		Priority:     "high",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Fix Mixed Content

1. Go to **SSL/TLS** > **Edge Certificates**
2. Enable **Automatic HTTPS Rewrites**
   - This automatically fixes mixed content by rewriting HTTP URLs to HTTPS

> This is the easiest fix and works for most cases.`,

			"apache": `## Apache - Fix Mixed Content

1. **Add CSP upgrade directive** to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "upgrade-insecure-requests"
</IfModule>
` + "```" + `

2. **Search and replace** HTTP URLs in your database/content with HTTPS equivalents.`,

			"nginx": `## Nginx - Fix Mixed Content

Add to your server block:

` + "```nginx" + `
add_header Content-Security-Policy "upgrade-insecure-requests" always;
` + "```" + `

Also update hardcoded HTTP URLs in your application.`,

			"litespeed": `## LiteSpeed - Fix Mixed Content

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "upgrade-insecure-requests"
</IfModule>
` + "```",

			"plesk": `## Plesk - Fix Mixed Content

In **Apache & nginx Settings**:

` + "```apache" + `
Header always set Content-Security-Policy "upgrade-insecure-requests"
` + "```",

			"cpanel": `## cPanel - Fix Mixed Content

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "upgrade-insecure-requests"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Fix Mixed Content

1. Install **Really Simple SSL** plugin (auto-fixes most mixed content)
2. Or install **Better Search Replace** plugin:
   - Search: ` + "`" + `http://yourdomain.com` + "`" + `
   - Replace: ` + "`" + `https://yourdomain.com` + "`" + `
   - Run on all tables
3. Update ` + "`" + `wp-config.php` + "`" + `:

` + "```php" + `
define('FORCE_SSL_ADMIN', true);
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 11. Server Header
	// -------------------------------------------------------------------------
	RemediationDB["Server Header Exposure"] = RemediationGuide{
		CheckName:    "Server Header Exposure",
		Title:        "Hide Server Header",
		Description:  "The Server header reveals your web server software and version, helping attackers target known vulnerabilities.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Hide Server Header

Cloudflare automatically replaces the origin server header with ` + "`" + `server: cloudflare` + "`" + `.

To remove it entirely:
1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. **Remove** the ` + "`" + `Server` + "`" + ` header`,

			"apache": `## Apache - Hide Server Header

In ` + "`" + `httpd.conf` + "`" + ` or ` + "`" + `apache2.conf` + "`" + `:

` + "```apache" + `
ServerTokens Prod
ServerSignature Off
` + "```" + `

To fully remove, install ` + "`" + `mod_security` + "`" + `:

` + "```apache" + `
SecServerSignature " "
` + "```",

			"nginx": `## Nginx - Hide Server Header

In ` + "`" + `nginx.conf` + "`" + ` (http block):

` + "```nginx" + `
server_tokens off;
` + "```" + `

To fully remove the header, install ` + "`" + `headers-more-nginx-module` + "`" + `:

` + "```nginx" + `
more_clear_headers Server;
` + "```",

			"litespeed": `## LiteSpeed - Hide Server Header

1. In **LiteSpeed Web Admin** > **Configuration** > **Server** > **General**
2. Set **Server Signature**: No
3. Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
ServerSignature Off
` + "```",

			"plesk": `## Plesk - Hide Server Header

1. Edit Apache configuration via **Apache & nginx Settings**
2. Add:

` + "```apache" + `
ServerTokens Prod
ServerSignature Off
` + "```",

			"cpanel": `## cPanel - Hide Server Header

1. In WHM: **Service Configuration** > **Apache Configuration** > **Global Configuration**
2. Set **ServerTokens** to ` + "`" + `Prod` + "`" + `
3. Set **ServerSignature** to ` + "`" + `Off` + "`",
		},
	}

	// -------------------------------------------------------------------------
	// 12. X-Powered-By
	// -------------------------------------------------------------------------
	RemediationDB["X-Powered-By Exposure"] = RemediationGuide{
		CheckName:    "X-Powered-By Exposure",
		Title:        "Remove X-Powered-By Header",
		Description:  "The X-Powered-By header reveals your backend technology (PHP, ASP.NET, etc.), aiding attackers.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Remove X-Powered-By

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add rule to **Remove** header: ` + "`" + `X-Powered-By` + "`",

			"apache": `## Apache - Remove X-Powered-By

For PHP, edit ` + "`" + `php.ini` + "`" + `:

` + "```ini" + `
expose_php = Off
` + "```" + `

Or via ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always unset X-Powered-By
</IfModule>
` + "```",

			"nginx": `## Nginx - Remove X-Powered-By

` + "```nginx" + `
proxy_hide_header X-Powered-By;
fastcgi_hide_header X-Powered-By;
` + "```" + `

Or with ` + "`" + `headers-more` + "`" + ` module:

` + "```nginx" + `
more_clear_headers X-Powered-By;
` + "```",

			"litespeed": `## LiteSpeed - Remove X-Powered-By

Edit ` + "`" + `php.ini` + "`" + `:

` + "```ini" + `
expose_php = Off
` + "```" + `

Or in ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
Header always unset X-Powered-By
` + "```",

			"plesk": `## Plesk - Remove X-Powered-By

1. Go to **Domains** > your domain > **PHP Settings**
2. Set ` + "`" + `expose_php` + "`" + ` to ` + "`" + `Off` + "`" + `
3. Or add to Apache directives:

` + "```apache" + `
Header always unset X-Powered-By
` + "```",

			"cpanel": `## cPanel - Remove X-Powered-By

1. Go to **MultiPHP INI Editor**
2. Set ` + "`" + `expose_php` + "`" + ` = ` + "`" + `Off` + "`" + `
3. Or edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always unset X-Powered-By
</IfModule>
` + "```",

			"wordpress": `## WordPress - Remove X-Powered-By

Add to ` + "`" + `functions.php` + "`" + `:

` + "```php" + `
header_remove('X-Powered-By');
` + "```" + `

And in ` + "`" + `php.ini` + "`" + `:

` + "```ini" + `
expose_php = Off
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 13. WordPress Version
	// -------------------------------------------------------------------------
	RemediationDB["WordPress Version"] = RemediationGuide{
		CheckName:    "WordPress Version",
		Title:        "Hide WordPress Version",
		Description:  "Exposing the WordPress version helps attackers find known vulnerabilities for that specific version.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Hide WP Version

Use a **Cloudflare Worker** to strip the generator meta tag, or handle it at the WordPress level (see WordPress guide).`,

			"apache": `## Apache - Hide WP Version

This is best handled at the WordPress application level. See the WordPress guide.

Alternatively, use ` + "`" + `mod_substitute` + "`" + ` to strip the meta tag (not recommended for performance).`,

			"nginx": `## Nginx - Hide WP Version

Use ` + "`" + `sub_filter` + "`" + ` to remove the generator tag:

` + "```nginx" + `
sub_filter '<meta name="generator"' '<!-- generator removed';
sub_filter_once on;
` + "```" + `

Better to handle at WordPress level.`,

			"litespeed": `## LiteSpeed - Hide WP Version

Handle at the WordPress application level. See the WordPress guide.`,

			"plesk": `## Plesk - Hide WP Version

Use the WordPress Toolkit in Plesk:
1. Go to **WordPress** > select your installation
2. Enable **Security** hardening options`,

			"cpanel": `## cPanel - Hide WP Version

Handle at the WordPress level. See the WordPress guide.`,

			"wordpress": `## WordPress - Hide Version

Add to your theme's ` + "`" + `functions.php` + "`" + ` or a custom plugin:

` + "```php" + `
// Remove generator meta tag
remove_action('wp_head', 'wp_generator');

// Remove version from RSS feeds
add_filter('the_generator', '__return_empty_string');

// Remove version from scripts and styles
function remove_wp_version_strings($src) {
    global $wp_version;
    parse_str(parse_url($src, PHP_URL_QUERY), $query);
    if (!empty($query['ver']) && $query['ver'] === $wp_version) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}
add_filter('script_loader_src', 'remove_wp_version_strings');
add_filter('style_loader_src', 'remove_wp_version_strings');
` + "```" + `

Also delete ` + "`" + `readme.html` + "`" + ` from the WordPress root directory.`,
		},
	}

	// -------------------------------------------------------------------------
	// 14. wp-login.php
	// -------------------------------------------------------------------------
	RemediationDB["WP Login Page Exposure"] = RemediationGuide{
		CheckName:    "WP Login Page Exposure",
		Title:        "Protect WordPress Login Page",
		Description:  "An exposed login page is the primary target for brute force attacks against WordPress sites.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Protect WP Login

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/wp-login.php") and not ip.src in {YOUR_IP}` + "`" + `
   - **Action**: Block or JS Challenge
3. Enable **Bot Fight Mode** under Security > Bots`,

			"apache": `## Apache - Protect WP Login

**Option 1: IP restriction**

` + "```apache" + `
<Files wp-login.php>
    Require ip 192.168.1.0/24
    Require ip YOUR.OFFICE.IP
</Files>
` + "```" + `

**Option 2: HTTP Auth**

` + "```apache" + `
<Files wp-login.php>
    AuthName "Admin Area"
    AuthType Basic
    AuthUserFile /path/to/.htpasswd
    Require valid-user
</Files>
` + "```",

			"nginx": `## Nginx - Protect WP Login

` + "```nginx" + `
location = /wp-login.php {
    allow 192.168.1.0/24;
    allow YOUR.OFFICE.IP;
    deny all;

    # Or use basic auth:
    # auth_basic "Admin Area";
    # auth_basic_user_file /etc/nginx/.htpasswd;

    include fastcgi_params;
    fastcgi_pass php;
}
` + "```",

			"litespeed": `## LiteSpeed - Protect WP Login

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files wp-login.php>
    Require ip YOUR.OFFICE.IP
</Files>
` + "```",

			"plesk": `## Plesk - Protect WP Login

Use **WordPress Toolkit** > **Security** > restrict login access.

Or add to Apache directives:

` + "```apache" + `
<Files wp-login.php>
    Require ip YOUR.OFFICE.IP
</Files>
` + "```",

			"cpanel": `## cPanel - Protect WP Login

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files wp-login.php>
    Require ip YOUR.OFFICE.IP
</Files>
` + "```",

			"wordpress": `## WordPress - Protect Login Page

**Option 1: Change login URL (Recommended)**

Install **WPS Hide Login** plugin:
1. Go to **Plugins** > **Add New** > search "WPS Hide Login"
2. Activate and set a custom login URL (e.g., ` + "`" + `/my-secret-login` + "`" + `)

**Option 2: Limit login attempts**

Install **Limit Login Attempts Reloaded**:
- Blocks IPs after failed attempts
- Configurable lockout duration

**Option 3: Two-Factor Authentication**

Install **WP 2FA** or **Google Authenticator** plugin.`,
		},
	}

	// -------------------------------------------------------------------------
	// 15. XML-RPC
	// -------------------------------------------------------------------------
	RemediationDB["WP XML-RPC Exposure"] = RemediationGuide{
		CheckName:    "WP XML-RPC Exposure",
		Title:        "Disable WordPress XML-RPC",
		Description:  "XML-RPC is exploited for brute force attacks, DDoS amplification, and pingback abuse.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block XML-RPC

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/xmlrpc.php")` + "`" + `
   - **Action**: Block`,

			"apache": `## Apache - Disable XML-RPC

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"nginx": `## Nginx - Disable XML-RPC

` + "```nginx" + `
location = /xmlrpc.php {
    deny all;
    return 403;
}
` + "```",

			"litespeed": `## LiteSpeed - Disable XML-RPC

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"plesk": `## Plesk - Disable XML-RPC

Use **WordPress Toolkit** > **Security** > disable XML-RPC.

Or add to Apache directives:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"cpanel": `## cPanel - Disable XML-RPC

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"wordpress": `## WordPress - Disable XML-RPC

**Option 1: Plugin (Recommended)**

Install **Disable XML-RPC** plugin.

**Option 2: functions.php**

` + "```php" + `
add_filter('xmlrpc_enabled', '__return_false');

// Also remove pingback header
add_filter('wp_headers', function($headers) {
    unset($headers['X-Pingback']);
    return $headers;
});
` + "```" + `

> **Note**: If you use the WordPress mobile app or Jetpack, you may need XML-RPC enabled. Consider using **Disable XML-RPC Pingback** instead.`,
		},
	}

	// -------------------------------------------------------------------------
	// 16. Directory Listing
	// -------------------------------------------------------------------------
	RemediationDB["Admin Panel Exposure"] = RemediationGuide{
		CheckName:    "Admin Panel Exposure",
		Title:        "Disable Directory Listing",
		Description:  "Directory listing exposes file structure and sensitive files to attackers.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Directory listing is a server-side configuration. Cloudflare cannot prevent it directly. Configure at the origin server level.`,

			"apache": `## Apache - Disable Directory Listing

` + "```apache" + `
Options -Indexes
` + "```" + `

Add to ` + "`" + `.htaccess` + "`" + ` or in the ` + "`" + `<Directory>` + "`" + ` block of your virtual host.`,

			"nginx": `## Nginx - Disable Directory Listing

` + "```nginx" + `
autoindex off;
` + "```" + `

This is off by default in Nginx. Check that no location block has ` + "`" + `autoindex on` + "`" + `.`,

			"litespeed": `## LiteSpeed - Disable Directory Listing

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
Options -Indexes
` + "```",

			"plesk": `## Plesk - Disable Directory Listing

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Uncheck **Indexes** in the Options section
3. Or add: ` + "`" + `Options -Indexes` + "`",

			"cpanel": `## cPanel - Disable Directory Listing

1. Go to **Advanced** > **Indexes**
2. Select **No Indexing** for your directories
3. Or edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
Options -Indexes
` + "```",

			"wordpress": `## WordPress - Disable Directory Listing

Add to ` + "`" + `.htaccess` + "`" + ` in WordPress root:

` + "```apache" + `
Options -Indexes
` + "```" + `

WordPress usually includes this by default.`,
		},
	}

	// -------------------------------------------------------------------------
	// 17. Robots.txt
	// -------------------------------------------------------------------------
	RemediationDB["Robots.txt Exposure"] = RemediationGuide{
		CheckName:    "Robots.txt Exposure",
		Title:        "Robots.txt Best Practices",
		Description:  "robots.txt should guide search engines without revealing sensitive directory paths.",
		Priority:     "low",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

robots.txt is served from your origin server. Configure it there.`,

			"apache": `## robots.txt Best Practices

Create/edit ` + "`" + `robots.txt` + "`" + ` in your document root:

` + "```" + `
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /tmp/

Sitemap: https://yourdomain.com/sitemap.xml
` + "```" + `

**Do NOT** list sensitive paths you want hidden - attackers read robots.txt too!`,

			"nginx": `## robots.txt Best Practices

Place ` + "`" + `robots.txt` + "`" + ` in your document root with:

` + "```" + `
User-agent: *
Disallow: /admin/
Disallow: /private/
Sitemap: https://yourdomain.com/sitemap.xml
` + "```" + `

Never list sensitive paths you want to keep secret.`,

			"litespeed": `## robots.txt Best Practices

Same as Apache - create ` + "`" + `robots.txt` + "`" + ` in your document root. Avoid listing truly sensitive paths.`,

			"plesk": `## Plesk - robots.txt

1. Go to **Domains** > your domain > **SEO Toolkit** (if available)
2. Or create ` + "`" + `robots.txt` + "`" + ` manually in the document root`,

			"cpanel": `## cPanel - robots.txt

1. Go to **File Manager** > document root
2. Create/edit ` + "`" + `robots.txt` + "`" + `
3. Avoid listing sensitive directory paths`,

			"wordpress": `## WordPress - robots.txt

WordPress auto-generates a virtual ` + "`" + `robots.txt` + "`" + `. To customize:

1. Install **Yoast SEO** plugin
2. Go to **SEO** > **Tools** > **File Editor** > **robots.txt**
3. Or create a physical ` + "`" + `robots.txt` + "`" + ` in the WP root directory`,
		},
	}

	// -------------------------------------------------------------------------
	// 18. Cache Headers
	// -------------------------------------------------------------------------
	RemediationDB["Cache Headers"] = RemediationGuide{
		CheckName:    "Cache Headers",
		Title:        "Configure Cache Headers",
		Description:  "Proper cache headers improve performance and reduce server load while ensuring fresh content delivery.",
		Priority:     "medium",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Cache Configuration

1. Go to **Caching** > **Configuration**
2. Set **Browser Cache TTL** to **Respect Existing Headers** or a specific duration
3. Create **Page Rules** for specific cache behavior:
   - Static assets: Cache Level = Cache Everything, Edge TTL = 1 month
   - API endpoints: Cache Level = Bypass`,

			"apache": `## Apache - Cache Headers

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType text/html "access plus 0 seconds"
</IfModule>

<IfModule mod_headers.c>
    <FilesMatch "\.(ico|jpg|jpeg|png|gif|svg|css|js|woff2)$">
        Header set Cache-Control "public, max-age=31536000, immutable"
    </FilesMatch>
    <FilesMatch "\.(html|php)$">
        Header set Cache-Control "no-cache, must-revalidate"
    </FilesMatch>
</IfModule>
` + "```",

			"nginx": `## Nginx - Cache Headers

` + "```nginx" + `
location ~* \.(ico|jpg|jpeg|png|gif|svg|css|js|woff2)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location ~* \.(html|php)$ {
    add_header Cache-Control "no-cache, must-revalidate";
}
` + "```",

			"litespeed": `## LiteSpeed - Cache Headers

LiteSpeed Cache plugin (for WordPress) handles this automatically.

For manual configuration, add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
` + "```",

			"plesk": `## Plesk - Cache Headers

In **Apache & nginx Settings**:

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
` + "```",

			"cpanel": `## cPanel - Cache Headers

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Cache Headers

**Option 1: Caching plugin (Recommended)**

Install **WP Super Cache**, **W3 Total Cache**, or **LiteSpeed Cache**.

**Option 2: .htaccess**

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType text/html "access plus 0 seconds"
</IfModule>
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 19. Brotli Compression
	// -------------------------------------------------------------------------
	RemediationDB["Brotli Compression"] = RemediationGuide{
		CheckName:    "Brotli Compression",
		Title:        "Enable Brotli Compression",
		Description:  "Brotli offers 15-25% better compression than gzip, significantly improving page load speed.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable Brotli

1. Go to **Speed** > **Optimization** > **Content Optimization**
2. Enable **Brotli**

> Cloudflare handles Brotli compression at the edge automatically.`,

			"apache": `## Apache - Enable Brotli

Ensure ` + "`" + `mod_brotli` + "`" + ` is installed (Apache 2.4.26+):

` + "```bash" + `
sudo a2enmod brotli
` + "```" + `

Add to your config:

` + "```apache" + `
<IfModule mod_brotli.c>
    AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css
    AddOutputFilterByType BROTLI_COMPRESS application/javascript application/json
    AddOutputFilterByType BROTLI_COMPRESS image/svg+xml application/xml
    BrotliCompressionQuality 6
</IfModule>
` + "```",

			"nginx": `## Nginx - Enable Brotli

Install ` + "`" + `ngx_brotli` + "`" + ` module, then add:

` + "```nginx" + `
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json application/javascript
             text/xml application/xml image/svg+xml;
` + "```",

			"litespeed": `## LiteSpeed - Enable Brotli

1. In **LiteSpeed Web Admin** > **Configuration** > **Server** > **Tuning**
2. Set **Enable Brotli Compression**: Yes
3. Set **Brotli Compression Level**: 6

Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_deflate.c>
    # LiteSpeed handles brotli automatically when enabled
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript
</IfModule>
` + "```",

			"plesk": `## Plesk - Enable Brotli

1. SSH into the server
2. Install brotli module for your web server
3. Configure in Apache/Nginx settings (see respective guides)`,

			"cpanel": `## cPanel - Enable Brotli

1. Check with your hosting provider if Brotli is available
2. If using Apache, the module needs to be compiled and enabled by root
3. As a fallback, ensure gzip is enabled via ` + "`" + `Optimize Website` + "`" + ` in cPanel`,
		},
	}

	// -------------------------------------------------------------------------
	// 20. Rate Limiting
	// -------------------------------------------------------------------------
	RemediationDB["Rate Limiting"] = RemediationGuide{
		CheckName:    "Rate Limiting",
		Title:        "Configure Rate Limiting",
		Description:  "Rate limiting protects against brute force attacks, DDoS, and API abuse by limiting request frequency.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Rate Limiting

1. Go to **Security** > **WAF** > **Rate limiting rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/wp-login.php")` + "`" + `
   - **Rate**: 5 requests per 10 seconds
   - **Action**: Block for 1 hour
3. For API endpoints:
   - **Rate**: 100 requests per minute
   - **Action**: JS Challenge

Also enable **Bot Fight Mode** under **Security** > **Bots**.`,

			"apache": `## Apache - Rate Limiting

Using ` + "`" + `mod_evasive` + "`" + `:

` + "```bash" + `
sudo apt install libapache2-mod-evasive
sudo a2enmod evasive
` + "```" + `

Configure ` + "`" + `/etc/apache2/mods-enabled/evasive.conf` + "`" + `:

` + "```apache" + `
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 5
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 600
</IfModule>
` + "```",

			"nginx": `## Nginx - Rate Limiting

` + "```nginx" + `
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    # Apply to login page
    location = /wp-login.php {
        limit_req zone=login burst=3 nodelay;
        # ... existing config
    }

    # Apply to API
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        # ... existing config
    }
}
` + "```",

			"litespeed": `## LiteSpeed - Rate Limiting

LiteSpeed has built-in anti-DDoS:

1. In **LiteSpeed Web Admin** > **Configuration** > **Server** > **Security**
2. Set:
   - **Per Client Throttling**: Bandwidth and request limits
   - **Static Requests/second**: 40
   - **Dynamic Requests/second**: 5

Or use ` + "`" + `.htaccess` + "`" + ` with mod_evasive equivalent settings.`,

			"plesk": `## Plesk - Rate Limiting

1. Install **Fail2Ban** via Plesk Extensions
2. Configure jails for your services
3. Or use the web server-level configuration (see Apache/Nginx guides)`,

			"cpanel": `## cPanel - Rate Limiting

1. Use **ModSecurity** (available in cPanel):
   - Go to **Security** > **ModSecurity**
   - Enable with OWASP ruleset
2. Install **CSF (ConfigServer Security & Firewall)**:
   - Provides connection rate limiting and flood protection
3. For WordPress, install **Wordfence** or **Limit Login Attempts** plugin`,

			"wordpress": `## WordPress - Rate Limiting

**Option 1: Security Plugin**

Install **Wordfence** or **Sucuri Security**:
- Built-in rate limiting
- Brute force protection
- Login attempt limits

**Option 2: Limit Login Attempts**

Install **Limit Login Attempts Reloaded** plugin:
1. Set max retries: 3
2. Lockout duration: 20 minutes
3. After lockouts: 24 hours

**Option 3: Application-level** (functions.php)

` + "```php" + `
// Basic throttle for REST API
add_filter('rest_authentication_errors', function($result) {
    $rate_key = 'rest_rate_' . $_SERVER['REMOTE_ADDR'];
    $count = get_transient($rate_key) ?: 0;
    if ($count > 100) {
        return new WP_Error('rate_limited', 'Too many requests', array('status' => 429));
    }
    set_transient($rate_key, $count + 1, 60);
    return $result;
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// Additional remediations for common checks
	// -------------------------------------------------------------------------

	RemediationDB["X-Content-Type-Options"] = RemediationGuide{
		CheckName:    "X-Content-Type-Options",
		Title:        "Set X-Content-Type-Options Header",
		Description:  "Prevents browsers from MIME-sniffing, which can lead to XSS attacks via uploaded files.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - X-Content-Type-Options

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add: ` + "`" + `X-Content-Type-Options: nosniff` + "`",

			"apache": `## Apache

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
add_header X-Content-Type-Options "nosniff" always;
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
Header always set X-Content-Type-Options "nosniff"
` + "```",

			"plesk": `## Plesk

Add to Apache directives: ` + "`" + `Header always set X-Content-Type-Options "nosniff"` + "`",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `: ` + "`" + `Header always set X-Content-Type-Options "nosniff"` + "`",

			"wordpress": `## WordPress

` + "```php" + `
add_action('send_headers', function() {
    header('X-Content-Type-Options: nosniff');
});
` + "```",
		},
	}

	RemediationDB["X-XSS-Protection"] = RemediationGuide{
		CheckName:    "X-XSS-Protection",
		Title:        "Set X-XSS-Protection Header",
		Description:  "Legacy browser XSS filter. Modern browsers rely on CSP, but this provides defense in depth.",
		Priority:     "low",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Add via Transform Rules: ` + "`" + `X-XSS-Protection: 1; mode=block` + "`",

			"apache": `## Apache

` + "```apache" + `
Header always set X-XSS-Protection "1; mode=block"
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
add_header X-XSS-Protection "1; mode=block" always;
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
Header always set X-XSS-Protection "1; mode=block"
` + "```",

			"plesk": `## Plesk

Add to Apache directives: ` + "`" + `Header always set X-XSS-Protection "1; mode=block"` + "`",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `: ` + "`" + `Header always set X-XSS-Protection "1; mode=block"` + "`",

			"wordpress": `## WordPress

` + "```php" + `
add_action('send_headers', function() {
    header('X-XSS-Protection: 1; mode=block');
});
` + "```",
		},
	}

	RemediationDB["Referrer-Policy"] = RemediationGuide{
		CheckName:    "Referrer-Policy",
		Title:        "Set Referrer-Policy Header",
		Description:  "Controls how much referrer information is sent with requests, protecting user privacy.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Add via Transform Rules: ` + "`" + `Referrer-Policy: strict-origin-when-cross-origin` + "`",

			"apache": `## Apache

` + "```apache" + `
Header always set Referrer-Policy "strict-origin-when-cross-origin"
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
Header always set Referrer-Policy "strict-origin-when-cross-origin"
` + "```",

			"plesk": `## Plesk

Add to Apache directives: ` + "`" + `Header always set Referrer-Policy "strict-origin-when-cross-origin"` + "`",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `: ` + "`" + `Header always set Referrer-Policy "strict-origin-when-cross-origin"` + "`",

			"wordpress": `## WordPress

` + "```php" + `
add_action('send_headers', function() {
    header('Referrer-Policy: strict-origin-when-cross-origin');
});
` + "```",
		},
	}

	RemediationDB["WP REST API User Enumeration"] = RemediationGuide{
		CheckName:    "WP REST API User Enumeration",
		Title:        "Block WordPress User Enumeration via REST API",
		Description:  "The REST API can expose usernames, enabling targeted brute force attacks.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block WP User Enumeration

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/wp-json/wp/v2/users")` + "`" + `
   - **Action**: Block`,

			"apache": `## Apache - Block User Enumeration

` + "```apache" + `
RewriteEngine On
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"nginx": `## Nginx - Block User Enumeration

` + "```nginx" + `
location ~* /wp-json/wp/v2/users {
    deny all;
    return 403;
}
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
RewriteEngine On
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"plesk": `## Plesk

Add to Apache directives:
` + "```apache" + `
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `:
` + "```apache" + `
RewriteEngine On
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"wordpress": `## WordPress - Block User Enumeration

**Option 1: Plugin**

Install **Disable REST API** or **Disable WP REST API** plugin.

**Option 2: functions.php**

` + "```php" + `
// Restrict users endpoint to authenticated users only
add_filter('rest_endpoints', function($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }
    return $endpoints;
});
` + "```",
		},
	}

	RemediationDB["WP Readme/License Exposure"] = RemediationGuide{
		CheckName:    "WP Readme/License Exposure",
		Title:        "Remove WordPress Readme and License Files",
		Description:  "These files reveal that the site runs WordPress and may expose the exact version.",
		Priority:     "low",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block Readme/License

1. Go to **Security** > **WAF** > **Custom Rules**
2. Block paths: ` + "`" + `(http.request.uri.path eq "/readme.html") or (http.request.uri.path eq "/license.txt")` + "`",

			"apache": `## Apache

` + "```apache" + `
<FilesMatch "^(readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
location ~* ^/(readme\.html|license\.txt)$ {
    deny all;
    return 404;
}
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
<FilesMatch "^(readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"plesk": `## Plesk

Delete the files or add to Apache directives:
` + "```apache" + `
<FilesMatch "^(readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"cpanel": `## cPanel

1. Go to **File Manager**
2. Delete ` + "`" + `readme.html` + "`" + ` and ` + "`" + `license.txt` + "`" + ` from WordPress root
3. Or block via ` + "`" + `.htaccess` + "`",

			"wordpress": `## WordPress

1. **Delete the files** from your WordPress root:
   - ` + "`" + `readme.html` + "`" + `
   - ` + "`" + `license.txt` + "`" + `

> **Note**: These files may be recreated after WordPress updates. Add a post-update script or use ` + "`" + `.htaccess` + "`" + ` to block access permanently.`,
		},
	}

	RemediationDB["WP Debug Mode"] = RemediationGuide{
		CheckName:    "WP Debug Mode",
		Title:        "Disable WordPress Debug Mode in Production",
		Description:  "Debug mode exposes PHP errors, file paths, and potentially sensitive data to visitors.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Debug mode is a WordPress/PHP configuration. Fix at the application level.`,

			"apache": `## Apache - Block debug.log

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```",

			"nginx": `## Nginx - Block debug.log

` + "```nginx" + `
location ~* /debug\.log$ {
    deny all;
    return 404;
}
` + "```",

			"litespeed": `## LiteSpeed - Block debug.log

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```",

			"plesk": `## Plesk

1. Use WordPress Toolkit to disable debug mode
2. Or edit wp-config.php directly`,

			"cpanel": `## cPanel

Edit ` + "`" + `wp-config.php` + "`" + ` via File Manager (see WordPress guide).`,

			"wordpress": `## WordPress - Disable Debug Mode

Edit ` + "`" + `wp-config.php` + "`" + `:

` + "```php" + `
// Disable debug mode in production
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

// If you need logging without display:
// define('WP_DEBUG', true);
// define('WP_DEBUG_LOG', true);
// define('WP_DEBUG_DISPLAY', false);
` + "```" + `

Also delete the existing debug.log:

` + "```bash" + `
rm /path/to/wordpress/wp-content/debug.log
` + "```" + `

Block access via ` + "`" + `.htaccess` + "`" + ` in ` + "`" + `wp-content/` + "`" + `:

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```",
		},
	}

	RemediationDB["HTTPS Enabled"] = RemediationGuide{
		CheckName:    "HTTPS Enabled",
		Title:        "Enable HTTPS with SSL/TLS Certificate",
		Description:  "HTTPS encrypts all data between the browser and server, preventing eavesdropping and tampering.",
		Priority:     "critical",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable HTTPS

1. Add your site to Cloudflare
2. Cloudflare provides a **free Universal SSL certificate** automatically
3. Go to **SSL/TLS** and set mode to **Full (Strict)**
4. Enable **Always Use HTTPS**`,

			"apache": `## Apache - Enable HTTPS with Let's Encrypt

` + "```bash" + `
sudo apt install certbot python3-certbot-apache
sudo certbot --apache -d yourdomain.com -d www.yourdomain.com
` + "```" + `

Certbot will automatically configure Apache and set up auto-renewal.`,

			"nginx": `## Nginx - Enable HTTPS with Let's Encrypt

` + "```bash" + `
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
` + "```",

			"litespeed": `## LiteSpeed - Enable HTTPS

1. In **LiteSpeed Web Admin** > **Listeners** > Add HTTPS listener on port 443
2. Use Let's Encrypt: ` + "`" + `certbot certonly --webroot -w /path/to/webroot -d yourdomain.com` + "`" + `
3. Configure the certificate path in the listener settings`,

			"plesk": `## Plesk - Enable HTTPS

1. Go to **Domains** > your domain > **SSL/TLS Certificates**
2. Click **Install** > **Let's Encrypt**
3. Check **Redirect from HTTP to HTTPS**`,

			"cpanel": `## cPanel - Enable HTTPS

1. Go to **Security** > **SSL/TLS**
2. Use **AutoSSL** (free) or install your own certificate
3. Enable **Force HTTPS** in domain settings`,
		},
	}

	RemediationDB["CORS Configuration"] = RemediationGuide{
		CheckName:    "CORS Configuration",
		Title:        "Configure CORS Properly",
		Description:  "Misconfigured CORS can allow unauthorized cross-origin access to your API and user data.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

CORS is typically configured at the origin server level. Use Transform Rules to add/modify CORS headers if needed.`,

			"apache": `## Apache - CORS Configuration

` + "```apache" + `
<IfModule mod_headers.c>
    # Allow specific origins only (never use *)
    SetEnvIf Origin "^https://(www\.)?yourdomain\.com$" ORIGIN=$0
    Header always set Access-Control-Allow-Origin "%{ORIGIN}e" env=ORIGIN
    Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
    Header always set Access-Control-Max-Age "3600"
</IfModule>
` + "```",

			"nginx": `## Nginx - CORS Configuration

` + "```nginx" + `
location /api/ {
    if ($http_origin ~* "^https://(www\.)?yourdomain\.com$") {
        add_header Access-Control-Allow-Origin $http_origin always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
        add_header Access-Control-Max-Age 3600 always;
    }

    if ($request_method = OPTIONS) {
        return 204;
    }
}
` + "```",

			"litespeed": `## LiteSpeed

Use the same ` + "`" + `.htaccess` + "`" + ` directives as Apache.`,

			"plesk": `## Plesk

Configure in Apache/Nginx settings for your domain.`,

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + ` with proper CORS headers (see Apache guide).`,

			"wordpress": `## WordPress - CORS

` + "```php" + `
add_action('init', function() {
    $allowed_origins = ['https://yourdomain.com', 'https://www.yourdomain.com'];
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (in_array($origin, $allowed_origins)) {
        header("Access-Control-Allow-Origin: $origin");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type, Authorization");
    }
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 29. Certificate Validity
	// -------------------------------------------------------------------------
	RemediationDB["Certificate Validity"] = RemediationGuide{
		CheckName:    "Certificate Validity",
		Title:        "Renew or Fix SSL/TLS Certificate",
		Description:  "An expired or soon-to-expire SSL certificate breaks HTTPS trust, causing browser warnings and blocking visitors.",
		Priority:     "critical",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Certificate Validity

Cloudflare manages edge certificates automatically. If issues arise:

1. Go to **SSL/TLS** > **Edge Certificates**
2. Verify **Universal SSL** is enabled
3. If expired, click **Disable Universal SSL**, wait 30 seconds, then **Enable** again
4. For **Origin Server**, generate a new origin certificate:
   - Click **Create Certificate**
   - Choose hostnames and validity period (up to 15 years)
   - Install the new certificate on your origin server

> Cloudflare edge certs auto-renew. Issues usually stem from the origin certificate.`,

			"apache": `## Apache - Certificate Renewal

**Using Let's Encrypt (Certbot):**

` + "```bash" + `
# Install Certbot
sudo apt install certbot python3-certbot-apache

# Obtain/renew certificate
sudo certbot --apache -d yourdomain.com -d www.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
` + "```" + `

**Enable auto-renewal cron:**

` + "```bash" + `
echo "0 3 * * * root certbot renew --quiet" | sudo tee /etc/cron.d/certbot-renew
` + "```",

			"nginx": `## Nginx - Certificate Renewal

**Using Let's Encrypt (Certbot):**

` + "```bash" + `
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain/renew certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
` + "```" + `

Certbot sets up a systemd timer for auto-renewal by default.`,

			"litespeed": `## LiteSpeed - Certificate Renewal

**Via LiteSpeed Admin Console:**

1. Go to **Listeners** > your listener > **SSL**
2. Upload new certificate and private key
3. Restart LiteSpeed

**Auto-renewal with Certbot:**

` + "```bash" + `
sudo certbot certonly --webroot -w /var/www/html -d yourdomain.com
# Then update LiteSpeed SSL paths and restart
` + "```",

			"plesk": `## Plesk - Certificate Renewal

1. Go to **Websites & Domains** > your domain
2. Click **SSL/TLS Certificates**
3. Click **Install** next to Let's Encrypt
4. Check **Keep secured** for auto-renewal
5. Select domain and www subdomain
6. Click **Get it free**

> Plesk handles Let's Encrypt auto-renewal natively.`,

			"cpanel": `## cPanel - Certificate Renewal

1. Go to **Security** > **SSL/TLS Status**
2. Select domains with expiring certificates
3. Click **Run AutoSSL** to renew
4. If AutoSSL is disabled, go to **SSL/TLS** > **Manage SSL Sites**
5. Install a new certificate manually or enable AutoSSL:
   - **WHM** > **Manage AutoSSL** > enable for your account`,

			"wordpress": `## WordPress - Certificate Renewal

SSL is managed at the server level, not WordPress. Follow the guide for your hosting platform above.

**After renewal, verify in WordPress:**

1. Go to **Settings** > **General**
2. Ensure both URLs start with ` + "`https://`" + `
3. Install **Really Simple SSL** plugin to fix mixed content issues
4. Clear any caching plugins after renewal`,
		},
	}

	// -------------------------------------------------------------------------
	// 30. CAA Record (Certificate Authority)
	// -------------------------------------------------------------------------
	RemediationDB["CAA Record (Certificate Authority)"] = RemediationGuide{
		CheckName:    "CAA Record (Certificate Authority)",
		Title:        "Add CAA DNS Record",
		Description:  "CAA records specify which Certificate Authorities are allowed to issue certificates for your domain, preventing unauthorized issuance.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add CAA Record

1. Go to **DNS** > **Records**
2. Click **Add record**
3. Set:
   - **Type**: CAA
   - **Name**: @ (or your domain)
   - **Tag**: Only allow specific hostnames
   - **CA domain name**: ` + "`letsencrypt.org`" + `
4. Add another CAA record for any other CA you use (e.g., ` + "`digicert.com`" + `)
5. Click **Save**

> Add a CAA record with tag ` + "`iodef`" + ` to receive violation reports via email.`,

			"apache": `## Apache / General DNS - Add CAA Record

CAA records are set in DNS, not in Apache. Add these records at your DNS provider:

` + "```" + `
yourdomain.com.  IN  CAA  0 issue "letsencrypt.org"
yourdomain.com.  IN  CAA  0 issuewild "letsencrypt.org"
yourdomain.com.  IN  CAA  0 iodef "mailto:security@yourdomain.com"
` + "```" + `

**Verify with:**

` + "```bash" + `
dig CAA yourdomain.com
` + "```",

			"nginx": `## Nginx / General DNS - Add CAA Record

CAA records are set in DNS, not in Nginx. Add at your DNS provider:

` + "```" + `
yourdomain.com.  IN  CAA  0 issue "letsencrypt.org"
yourdomain.com.  IN  CAA  0 issuewild "letsencrypt.org"
yourdomain.com.  IN  CAA  0 iodef "mailto:security@yourdomain.com"
` + "```" + `

Replace ` + "`letsencrypt.org`" + ` with your actual CA. Common values: ` + "`digicert.com`" + `, ` + "`sectigo.com`" + `, ` + "`letsencrypt.org`" + `.`,

			"litespeed": `## LiteSpeed / General DNS

CAA records are configured in your DNS provider, not LiteSpeed. See the Apache/Nginx guide for DNS record format.`,

			"plesk": `## Plesk - Add CAA Record

1. Go to **Websites & Domains** > your domain
2. Click **DNS Settings**
3. Click **Add Record**
4. Select type **CAA**
5. Set **Flag**: 0, **Tag**: issue, **Value**: ` + "`letsencrypt.org`" + `
6. Add additional records for ` + "`issuewild`" + ` and ` + "`iodef`" + `
7. Click **OK** and **Apply**`,

			"cpanel": `## cPanel - Add CAA Record

1. Go to **Domains** > **Zone Editor**
2. Click **Manage** next to your domain
3. Click **Add Record** > **Add CAA Record**
4. Set:
   - **Flag**: 0
   - **Tag**: issue
   - **Value**: ` + "`letsencrypt.org`" + `
5. Add another for ` + "`issuewild`" + ` and ` + "`iodef`" + `
6. Click **Save**`,

			"wordpress": `## WordPress - CAA Record

CAA records are DNS-level settings, not WordPress settings. Configure them at your domain registrar or DNS provider (Cloudflare, cPanel, Plesk, etc.).

**Recommended records:**
- ` + "`0 issue \"letsencrypt.org\"`" + ` (allow Let's Encrypt)
- ` + "`0 issuewild \"letsencrypt.org\"`" + ` (allow wildcard certs)
- ` + "`0 iodef \"mailto:you@yourdomain.com\"`" + ` (violation reports)`,
		},
	}

	// -------------------------------------------------------------------------
	// 31. CMS Detection
	// -------------------------------------------------------------------------
	RemediationDB["CMS Detection"] = RemediationGuide{
		CheckName:    "CMS Detection",
		Title:        "Hide CMS Fingerprint",
		Description:  "Exposing your CMS type and version helps attackers find known vulnerabilities. Hiding these fingerprints reduces your attack surface.",
		Priority:     "medium",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Hide CMS Fingerprint

Use a **Transform Rule** to strip revealing headers:

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Create rules to **Remove** these headers:
   - ` + "`X-Powered-By`" + `
   - ` + "`X-Generator`" + `
3. Use a **Worker** to remove CMS meta tags from HTML responses if needed.`,

			"apache": `## Apache - Hide CMS Fingerprint

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
# Remove server signature
ServerSignature Off

# Remove X-Powered-By
<IfModule mod_headers.c>
    Header unset X-Powered-By
    Header unset X-Generator
</IfModule>

# Block access to common CMS fingerprint files
<FilesMatch "(readme\.html|license\.txt|changelog\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"nginx": `## Nginx - Hide CMS Fingerprint

Add to your ` + "`server`" + ` block:

` + "```nginx" + `
# Hide server version
server_tokens off;

# Remove revealing headers
proxy_hide_header X-Powered-By;
proxy_hide_header X-Generator;

# Block fingerprint files
location ~* (readme\.html|license\.txt|changelog\.txt)$ {
    return 404;
}
` + "```" + `

Then reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Hide CMS Fingerprint

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
ServerSignature Off
<IfModule mod_headers.c>
    Header unset X-Powered-By
    Header unset X-Generator
</IfModule>
<FilesMatch "(readme\.html|license\.txt|changelog\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"plesk": `## Plesk - Hide CMS Fingerprint

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:
   ` + "`Header unset X-Powered-By`" + `
3. Add to **Additional nginx directives**:
   ` + "`proxy_hide_header X-Powered-By;`" + `
4. Click **Apply**`,

			"cpanel": `## cPanel - Hide CMS Fingerprint

1. Open **File Manager** > navigate to document root
2. Edit ` + "`" + `.htaccess` + "`" + ` and add:

` + "```apache" + `
<IfModule mod_headers.c>
    Header unset X-Powered-By
</IfModule>
<FilesMatch "(readme\.html|license\.txt|changelog\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"wordpress": `## WordPress - Hide CMS Fingerprint

Add to your theme's ` + "`functions.php`" + ` or a custom plugin:

` + "```php" + `
// Remove WordPress version from head and feeds
remove_action('wp_head', 'wp_generator');

// Remove version from scripts and styles
add_filter('style_loader_src', function($src) { return remove_query_arg('ver', $src); });
add_filter('script_loader_src', function($src) { return remove_query_arg('ver', $src); });

// Remove X-Powered-By
header_remove('X-Powered-By');
` + "```" + `

Also delete or block ` + "`readme.html`" + ` and ` + "`license.txt`" + ` from your WordPress root.`,
		},
	}

	// -------------------------------------------------------------------------
	// 32. CDN/DDoS Protection Service
	// -------------------------------------------------------------------------
	RemediationDB["CDN/DDoS Protection Service"] = RemediationGuide{
		CheckName:    "CDN/DDoS Protection Service",
		Title:        "Enable CDN and DDoS Protection",
		Description:  "A CDN improves performance and protects against DDoS attacks by distributing traffic across global edge servers.",
		Priority:     "high",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - CDN/DDoS Protection

If you already use Cloudflare, ensure protection is active:

1. Verify your DNS records show **Proxied** (orange cloud icon)
2. Go to **Security** > **DDoS** and review settings
3. Enable **Bot Fight Mode** under **Security** > **Bots**
4. Set **Security Level** to **Medium** or higher under **Security** > **Settings**
5. Enable **Browser Integrity Check**

> Records showing "DNS only" (grey cloud) bypass Cloudflare protection.`,

			"apache": `## Apache - Enable Cloudflare CDN (Free)

1. Sign up at [cloudflare.com](https://cloudflare.com) (free plan available)
2. Add your domain and follow the setup wizard
3. Update your domain's nameservers to Cloudflare's
4. Wait for DNS propagation (up to 24 hours)
5. Once active, install ` + "`mod_cloudflare`" + ` to restore real visitor IPs:

` + "```bash" + `
sudo apt install libapache2-mod-cloudflare
sudo systemctl restart apache2
` + "```",

			"nginx": `## Nginx - Enable Cloudflare CDN (Free)

1. Sign up at [cloudflare.com](https://cloudflare.com)
2. Add your domain and update nameservers
3. Restore real visitor IPs in Nginx:

` + "```nginx" + `
# Add Cloudflare IP ranges to restore real IPs
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 173.245.48.0/20;
# ... add all Cloudflare ranges from https://www.cloudflare.com/ips/
real_ip_header CF-Connecting-IP;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Enable Cloudflare CDN

1. Sign up at [cloudflare.com](https://cloudflare.com) and add your domain
2. Update nameservers at your registrar
3. LiteSpeed handles Cloudflare IPs automatically with its built-in real IP module
4. Verify: Go to **LiteSpeed Admin** > **Server** > **General** > enable **Use Client IP in Header**`,

			"plesk": `## Plesk - Enable Cloudflare CDN

1. In Plesk, go to **Extensions** > search **Cloudflare**
2. Install the **Cloudflare** extension
3. Log in with your Cloudflare account
4. Enable Cloudflare for your domain
5. Alternatively, set up manually at cloudflare.com and update nameservers`,

			"cpanel": `## cPanel - Enable Cloudflare CDN

**Option 1: cPanel Cloudflare Plugin** (if available)

1. Go to **Software** > **Cloudflare**
2. Create or link your Cloudflare account
3. Enable for your domain

**Option 2: Manual Setup**

1. Sign up at [cloudflare.com](https://cloudflare.com)
2. Add your domain and change nameservers
3. Ask your hosting provider to install mod_cloudflare for real IP restoration`,

			"wordpress": `## WordPress - Enable CDN/DDoS Protection

1. Sign up at [cloudflare.com](https://cloudflare.com) (free plan)
2. Add your domain and update nameservers
3. Install the **Cloudflare** WordPress plugin:
   - **Plugins** > **Add New** > search "Cloudflare"
   - Activate and enter your API token
4. Enable **Automatic Platform Optimization (APO)** for best WordPress performance

> The free Cloudflare plan includes DDoS protection, CDN, and basic WAF.`,
		},
	}

	// -------------------------------------------------------------------------
	// 33. Cookie Security
	// -------------------------------------------------------------------------
	RemediationDB["Cookie Security"] = RemediationGuide{
		CheckName:    "Cookie Security",
		Title:        "Set Secure Cookie Flags",
		Description:  "Cookies without Secure, HttpOnly, and SameSite flags are vulnerable to interception, XSS theft, and CSRF attacks.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Cookie Security

Cloudflare cannot modify application-set cookies directly. However:

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Use a **Worker** to rewrite ` + "`Set-Cookie`" + ` headers adding flags:

` + "```javascript" + `
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const response = await fetch(request);
  const newResponse = new Response(response.body, response);
  const cookies = newResponse.headers.getAll('Set-Cookie');
  newResponse.headers.delete('Set-Cookie');
  for (const cookie of cookies) {
    let secured = cookie;
    if (!cookie.includes('Secure')) secured += '; Secure';
    if (!cookie.includes('HttpOnly')) secured += '; HttpOnly';
    if (!cookie.includes('SameSite')) secured += '; SameSite=Lax';
    newResponse.headers.append('Set-Cookie', secured);
  }
  return newResponse;
}
` + "```",

			"apache": `## Apache - Cookie Security

Add to ` + "`" + `.htaccess` + "`" + ` or virtual host:

` + "```apache" + `
<IfModule mod_headers.c>
    # Add Secure and HttpOnly to all cookies
    Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
</IfModule>
` + "```" + `

Enable ` + "`mod_headers`" + `: ` + "`sudo a2enmod headers && sudo systemctl restart apache2`" + ``,

			"nginx": `## Nginx - Cookie Security

Add to your ` + "`server`" + ` or ` + "`location`" + ` block:

` + "```nginx" + `
# For proxied applications
proxy_cookie_flags ~ secure httponly samesite=lax;

# Or via header manipulation
more_set_headers 'Set-Cookie: $sent_http_set_cookie; Secure; HttpOnly; SameSite=Lax';
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + `

> ` + "`proxy_cookie_flags`" + ` requires nginx 1.19.3+.`,

			"litespeed": `## LiteSpeed - Cookie Security

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
</IfModule>
` + "```",

			"plesk": `## Plesk - Cookie Security

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. In **Additional Apache directives**, add:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
</IfModule>
` + "```" + `

3. Click **Apply**`,

			"cpanel": `## cPanel - Cookie Security

Edit ` + "`" + `.htaccess` + "`" + ` in your document root:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Cookie Security

**Option 1: wp-config.php**

Add before "That's all, stop editing!":

` + "```php" + `
@ini_set('session.cookie_httponly', true);
@ini_set('session.cookie_secure', true);
@ini_set('session.cookie_samesite', 'Lax');
` + "```" + `

**Option 2: functions.php**

` + "```php" + `
add_action('init', function() {
    if (PHP_VERSION_ID >= 70300) {
        ini_set('session.cookie_samesite', 'Lax');
    }
}, 1);
` + "```" + `

**Option 3:** Install **HTTP Headers** plugin and configure cookie flags.`,
		},
	}

	// -------------------------------------------------------------------------
	// 34. Cross-Origin-Embedder-Policy
	// -------------------------------------------------------------------------
	RemediationDB["Cross-Origin-Embedder-Policy"] = RemediationGuide{
		CheckName:    "Cross-Origin-Embedder-Policy",
		Title:        "Set Cross-Origin-Embedder-Policy Header",
		Description:  "COEP prevents loading cross-origin resources that don't explicitly grant permission, enabling features like SharedArrayBuffer.",
		Priority:     "low",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - COEP Header

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Click **Create rule**
3. Set:
   - **Header name**: ` + "`Cross-Origin-Embedder-Policy`" + `
   - **Value**: ` + "`require-corp`" + `
4. Deploy

> **Warning**: This can break third-party resources (images, scripts, iframes). Test with ` + "`credentialless`" + ` first.`,

			"apache": `## Apache - COEP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Embedder-Policy "require-corp"
</IfModule>
` + "```" + `

> **Warning for WordPress/CMS sites**: This header can break third-party embeds, images, and scripts. Use ` + "`credentialless`" + ` instead of ` + "`require-corp`" + ` if you load external resources.`,

			"nginx": `## Nginx - COEP Header

Add inside your ` + "`server`" + ` block:

` + "```nginx" + `
add_header Cross-Origin-Embedder-Policy "require-corp" always;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + `

> **Warning**: Use ` + "`credentialless`" + ` instead of ` + "`require-corp`" + ` if your site loads third-party resources.`,

			"litespeed": `## LiteSpeed - COEP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Embedder-Policy "require-corp"
</IfModule>
` + "```",

			"plesk": `## Plesk - COEP Header

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:
   ` + "`Header always set Cross-Origin-Embedder-Policy \"require-corp\"`" + `
3. Click **Apply**`,

			"cpanel": `## cPanel - COEP Header

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Embedder-Policy "require-corp"
</IfModule>
` + "```",

			"wordpress": `## WordPress - COEP Header

> **Warning**: ` + "`require-corp`" + ` will likely break WordPress sites that use external images, embeds, or CDNs. Use ` + "`credentialless`" + ` instead.

` + "```php" + `
add_action('send_headers', function() {
    header('Cross-Origin-Embedder-Policy: credentialless');
});
` + "```" + `

Or use the **HTTP Headers** plugin to add the header with a safe value.`,
		},
	}

	// -------------------------------------------------------------------------
	// 35. Cross-Origin-Opener-Policy
	// -------------------------------------------------------------------------
	RemediationDB["Cross-Origin-Opener-Policy"] = RemediationGuide{
		CheckName:    "Cross-Origin-Opener-Policy",
		Title:        "Set Cross-Origin-Opener-Policy Header",
		Description:  "COOP isolates your browsing context, preventing cross-origin documents from accessing your window object.",
		Priority:     "low",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - COOP Header

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Click **Create rule**
3. Set:
   - **Header name**: ` + "`Cross-Origin-Opener-Policy`" + `
   - **Value**: ` + "`same-origin`" + `
4. Deploy`,

			"apache": `## Apache - COOP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Opener-Policy "same-origin"
</IfModule>
` + "```",

			"nginx": `## Nginx - COOP Header

Add inside your ` + "`server`" + ` block:

` + "```nginx" + `
add_header Cross-Origin-Opener-Policy "same-origin" always;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - COOP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Opener-Policy "same-origin"
</IfModule>
` + "```",

			"plesk": `## Plesk - COOP Header

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:
   ` + "`Header always set Cross-Origin-Opener-Policy \"same-origin\"`" + `
3. Click **Apply**`,

			"cpanel": `## cPanel - COOP Header

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Opener-Policy "same-origin"
</IfModule>
` + "```",

			"wordpress": `## WordPress - COOP Header

` + "```php" + `
add_action('send_headers', function() {
    header('Cross-Origin-Opener-Policy: same-origin');
});
` + "```" + `

Or use the **HTTP Headers** plugin.

> This is generally safe for WordPress sites. Use ` + "`same-origin-allow-popups`" + ` if you use OAuth popups or payment gateways.`,
		},
	}

	// -------------------------------------------------------------------------
	// 36. Cross-Origin-Resource-Policy
	// -------------------------------------------------------------------------
	RemediationDB["Cross-Origin-Resource-Policy"] = RemediationGuide{
		CheckName:    "Cross-Origin-Resource-Policy",
		Title:        "Set Cross-Origin-Resource-Policy Header",
		Description:  "CORP prevents other origins from reading your resources, protecting against speculative side-channel attacks like Spectre.",
		Priority:     "low",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - CORP Header

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Click **Create rule**
3. Set:
   - **Header name**: ` + "`Cross-Origin-Resource-Policy`" + `
   - **Value**: ` + "`same-origin`" + ` (or ` + "`cross-origin`" + ` if resources are shared)
4. Deploy`,

			"apache": `## Apache - CORP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Resource-Policy "same-origin"
</IfModule>
` + "```" + `

> Use ` + "`cross-origin`" + ` if your resources need to be loaded by other sites (e.g., CDN, public API).`,

			"nginx": `## Nginx - CORP Header

Add inside your ` + "`server`" + ` block:

` + "```nginx" + `
add_header Cross-Origin-Resource-Policy "same-origin" always;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - CORP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Resource-Policy "same-origin"
</IfModule>
` + "```",

			"plesk": `## Plesk - CORP Header

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:
   ` + "`Header always set Cross-Origin-Resource-Policy \"same-origin\"`" + `
3. Click **Apply**`,

			"cpanel": `## cPanel - CORP Header

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Cross-Origin-Resource-Policy "same-origin"
</IfModule>
` + "```",

			"wordpress": `## WordPress - CORP Header

` + "```php" + `
add_action('send_headers', function() {
    header('Cross-Origin-Resource-Policy: same-origin');
});
` + "```" + `

> Use ` + "`cross-origin`" + ` if your site serves images/fonts used by other domains, or if you use a CDN.`,
		},
	}

	// -------------------------------------------------------------------------
	// 37. OCSP Stapling
	// -------------------------------------------------------------------------
	RemediationDB["OCSP Stapling"] = RemediationGuide{
		CheckName:    "OCSP Stapling",
		Title:        "Enable OCSP Stapling",
		Description:  "OCSP Stapling improves SSL/TLS handshake speed and privacy by having the server provide certificate revocation status directly.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - OCSP Stapling

Cloudflare enables OCSP Stapling automatically for all edge certificates. No action needed.

To verify, go to **SSL/TLS** > **Edge Certificates** and confirm your certificate is active.`,

			"apache": `## Apache - Enable OCSP Stapling

Add to your virtual host or ` + "`ssl.conf`" + `:

` + "```apache" + `
SSLUseStapling On
SSLStaplingCache shmcb:/tmp/stapling_cache(128000)
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors off
` + "```" + `

Restart: ` + "`sudo systemctl restart apache2`" + `

**Verify:**

` + "```bash" + `
openssl s_client -connect yourdomain.com:443 -status </dev/null 2>&1 | grep -i "OCSP Response Status"
` + "```",

			"nginx": `## Nginx - Enable OCSP Stapling

Add inside your ` + "`server`" + ` block (HTTPS):

` + "```nginx" + `
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/yourdomain.com/chain.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + `

**Verify:**

` + "```bash" + `
openssl s_client -connect yourdomain.com:443 -status </dev/null 2>&1 | grep -i "OCSP Response Status"
` + "```",

			"litespeed": `## LiteSpeed - Enable OCSP Stapling

1. Go to **LiteSpeed Admin** > **Listeners** > your listener > **SSL**
2. Set **OCSP Stapling** to **Yes**
3. Optionally set **OCSP Responder** to your CA's OCSP URL
4. Restart LiteSpeed

Or add to your virtual host config:
` + "`stapling: 1`" + ``,

			"plesk": `## Plesk - Enable OCSP Stapling

1. Go to **Tools & Settings** > **SSL/TLS Certificates**
2. Or configure in the web server config:
   - For Apache: Add ` + "`SSLUseStapling On`" + ` in additional directives
   - For Nginx: Add ` + "`ssl_stapling on;`" + ` in additional directives
3. Apply and restart web server`,

			"cpanel": `## cPanel - Enable OCSP Stapling

1. Access **WHM** (requires root)
2. Go to **Service Configuration** > **Apache Configuration** > **Global Configuration**
3. Add to the SSL configuration:
   ` + "`SSLUseStapling On`" + `
4. Or edit ` + "`/etc/apache2/conf.d/ssl.conf`" + ` manually and add:

` + "```apache" + `
SSLUseStapling On
SSLStaplingCache shmcb:/tmp/stapling_cache(128000)
` + "```" + `

5. Restart Apache: ` + "`sudo systemctl restart httpd`" + ``,

			"wordpress": `## WordPress - OCSP Stapling

OCSP Stapling is configured at the web server level, not WordPress.

Follow the guide for your server (Apache, Nginx, or LiteSpeed) above. If you are on shared hosting, contact your host to enable OCSP Stapling.`,
		},
	}

	// -------------------------------------------------------------------------
	// 38. Compression Ratio
	// -------------------------------------------------------------------------
	RemediationDB["Compression Ratio"] = RemediationGuide{
		CheckName:    "Compression Ratio",
		Title:        "Enable Gzip/Brotli Compression",
		Description:  "Compression reduces page load times and bandwidth usage by compressing responses before sending them to the browser.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable Compression

Cloudflare compresses responses automatically. To verify:

1. Go to **Speed** > **Optimization** > **Content Optimization**
2. Ensure **Brotli** is enabled (on by default)
3. Cloudflare also applies Gzip automatically

> If compression ratio is still low, ensure your origin server is not sending pre-compressed responses that conflict.`,

			"apache": `## Apache - Enable Gzip Compression

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/css
    AddOutputFilterByType DEFLATE text/javascript application/javascript application/json
    AddOutputFilterByType DEFLATE text/xml application/xml application/xhtml+xml
    AddOutputFilterByType DEFLATE image/svg+xml application/font-woff application/font-woff2
</IfModule>
` + "```" + `

Enable mod_deflate: ` + "`sudo a2enmod deflate && sudo systemctl restart apache2`" + ``,

			"nginx": `## Nginx - Enable Gzip and Brotli

Add to ` + "`http`" + ` block in ` + "`nginx.conf`" + `:

` + "```nginx" + `
# Gzip
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml image/svg+xml;

# Brotli (if module installed)
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json application/javascript text/xml application/xml image/svg+xml;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Enable Compression

1. Go to **LiteSpeed Admin** > **Server Configuration** > **Tuning**
2. Under **Enable GZIP Compression**: set to **Yes**
3. Set **Compressible Types** to:
   ` + "`text/*, application/javascript, application/json, application/xml, image/svg+xml`" + `

Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/css application/javascript application/json
</IfModule>
` + "```",

			"plesk": `## Plesk - Enable Compression

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Enable **nginx gzip compression** checkbox
3. Or add to **Additional Apache directives**:

` + "```apache" + `
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/css application/javascript application/json
</IfModule>
` + "```" + `

4. Click **Apply**`,

			"cpanel": `## cPanel - Enable Compression

1. Go to **Software** > **Optimize Website**
2. Select **Compress All Content**
3. Click **Update Settings**

Or edit ` + "`" + `.htaccess` + "`" + ` manually:

` + "```apache" + `
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/css application/javascript application/json text/xml
</IfModule>
` + "```",

			"wordpress": `## WordPress - Enable Compression

**Option 1: Plugin**

Install **WP Super Cache**, **W3 Total Cache**, or **LiteSpeed Cache** - all support Gzip compression.

**Option 2: .htaccess**

Add to ` + "`" + `.htaccess` + "`" + ` (before WordPress rules):

` + "```apache" + `
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/css
    AddOutputFilterByType DEFLATE application/javascript application/json text/xml
</IfModule>
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 39. Meta Tags Quality
	// -------------------------------------------------------------------------
	RemediationDB["Meta Tags Quality"] = RemediationGuide{
		CheckName:    "Meta Tags Quality",
		Title:        "Add Proper HTML Meta Tags",
		Description:  "Proper meta tags improve SEO rankings, social sharing previews, and browser behavior.",
		Priority:     "low",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Meta tags are set in your HTML, not at the CDN level. Modify your site's source code or CMS settings.`,

			"apache": `## Apache / Static Sites

Add these meta tags inside ` + "`<head>`" + ` in your HTML files:

` + "```html" + `
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Your page description (150-160 characters)">
<meta name="keywords" content="keyword1, keyword2, keyword3">
<meta name="author" content="Your Name or Organization">
<meta name="robots" content="index, follow">
<link rel="canonical" href="https://yourdomain.com/page-url">
` + "```",

			"nginx": `## Nginx / Static Sites

Meta tags are set in HTML source, not Nginx config. Edit your HTML ` + "`<head>`" + ` to include:

` + "```html" + `
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Page description (150-160 chars)">
<meta name="robots" content="index, follow">
<link rel="canonical" href="https://yourdomain.com/page-url">
` + "```",

			"litespeed": `## LiteSpeed

Meta tags are set in your HTML source. See the Apache/static site guide for the required meta tags.`,

			"plesk": `## Plesk

Edit your site's HTML files via **File Manager** or your CMS to include proper meta tags in the ` + "`<head>`" + ` section.`,

			"cpanel": `## cPanel

Use **File Manager** to edit your HTML files. Add meta tags in the ` + "`<head>`" + ` section of each page.`,

			"wordpress": `## WordPress - Meta Tags

**Option 1: SEO Plugin (Recommended)**

Install **Yoast SEO** or **Rank Math**:
1. **Plugins** > **Add New** > search "Yoast SEO" or "Rank Math"
2. Activate and run the setup wizard
3. Edit each page/post and fill in the **SEO title** and **meta description** fields

**Option 2: Theme functions**

` + "```php" + `
add_action('wp_head', function() {
    if (is_front_page()) {
        echo '<meta name="description" content="Your site description">';
    }
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 40. Open Graph Tags
	// -------------------------------------------------------------------------
	RemediationDB["Open Graph Tags"] = RemediationGuide{
		CheckName:    "Open Graph Tags",
		Title:        "Add Open Graph Meta Tags",
		Description:  "Open Graph tags control how your pages appear when shared on social media platforms like Facebook, LinkedIn, and Twitter.",
		Priority:     "low",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Open Graph tags must be set in your HTML source code, not at the CDN level.`,

			"apache": `## Apache / Static Sites

Add inside ` + "`<head>`" + `:

` + "```html" + `
<meta property="og:title" content="Page Title">
<meta property="og:description" content="Brief description of the page">
<meta property="og:image" content="https://yourdomain.com/image.jpg">
<meta property="og:url" content="https://yourdomain.com/page-url">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Your Site Name">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Page Title">
<meta name="twitter:description" content="Brief description">
<meta name="twitter:image" content="https://yourdomain.com/image.jpg">
` + "```",

			"nginx": `## Nginx / Static Sites

Add OG tags in your HTML ` + "`<head>`" + `. See the Apache guide for the complete list of recommended OG tags.`,

			"litespeed": `## LiteSpeed

Open Graph tags are set in HTML, not server config. See the Apache guide for required tags.`,

			"plesk": `## Plesk

Edit your HTML files to add Open Graph tags in the ` + "`<head>`" + ` section.`,

			"cpanel": `## cPanel

Edit your HTML files via **File Manager** to add OG meta tags.`,

			"wordpress": `## WordPress - Open Graph Tags

**Option 1: SEO Plugin (Recommended)**

**Yoast SEO** or **Rank Math** automatically generate OG tags:
1. Install and activate the plugin
2. Go to **SEO** > **Social** and configure your default image
3. Edit each page/post to customize OG title, description, and image

**Option 2: functions.php**

` + "```php" + `
add_action('wp_head', function() {
    if (is_singular()) {
        $title = get_the_title();
        $desc = get_the_excerpt();
        $image = get_the_post_thumbnail_url(null, 'large');
        $url = get_permalink();
        echo "<meta property=\"og:title\" content=\"$title\">\n";
        echo "<meta property=\"og:description\" content=\"$desc\">\n";
        if ($image) echo "<meta property=\"og:image\" content=\"$image\">\n";
        echo "<meta property=\"og:url\" content=\"$url\">\n";
        echo "<meta property=\"og:type\" content=\"article\">\n";
    }
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 41. Sitemap Accessibility
	// -------------------------------------------------------------------------
	RemediationDB["Sitemap Accessibility"] = RemediationGuide{
		CheckName:    "Sitemap Accessibility",
		Title:        "Create and Configure XML Sitemap",
		Description:  "An XML sitemap helps search engines discover and index all pages on your site efficiently.",
		Priority:     "low",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Sitemaps must be generated by your application/CMS. Cloudflare does not generate sitemaps.`,

			"apache": `## Apache / Static Sites

1. Create ` + "`sitemap.xml`" + ` in your document root:

` + "```xml" + `
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://yourdomain.com/</loc>
    <lastmod>2024-01-01</lastmod>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://yourdomain.com/about</loc>
    <lastmod>2024-01-01</lastmod>
    <priority>0.8</priority>
  </url>
</urlset>
` + "```" + `

2. Reference it in ` + "`robots.txt`" + `: ` + "`Sitemap: https://yourdomain.com/sitemap.xml`" + `
3. Submit to [Google Search Console](https://search.google.com/search-console)`,

			"nginx": `## Nginx / Static Sites

1. Create ` + "`sitemap.xml`" + ` in your document root (see Apache guide for format)
2. Ensure Nginx serves it with correct content type:

` + "```nginx" + `
location = /sitemap.xml {
    types { application/xml xml; }
    default_type application/xml;
}
` + "```" + `

3. Add ` + "`Sitemap: https://yourdomain.com/sitemap.xml`" + ` to ` + "`robots.txt`" + ``,

			"litespeed": `## LiteSpeed

Create ` + "`sitemap.xml`" + ` in your document root. LiteSpeed serves it automatically. See the Apache guide for the XML format.`,

			"plesk": `## Plesk

1. Use **SEO Toolkit** (if available) to auto-generate a sitemap
2. Or manually create ` + "`sitemap.xml`" + ` in your document root via **File Manager**
3. Submit to Google Search Console`,

			"cpanel": `## cPanel

1. Create ` + "`sitemap.xml`" + ` in your ` + "`public_html`" + ` via **File Manager**
2. Use a sitemap generator tool (e.g., xml-sitemaps.com) for large sites
3. Add reference in ` + "`robots.txt`" + `: ` + "`Sitemap: https://yourdomain.com/sitemap.xml`" + ``,

			"wordpress": `## WordPress - Sitemap

**WordPress 5.5+ includes a built-in sitemap** at ` + "`/wp-sitemap.xml`" + `.

**For more control, use a plugin:**

1. Install **Yoast SEO** or **Rank Math**
2. Both auto-generate comprehensive XML sitemaps
3. Go to **SEO** > **General** > **Features** and ensure XML Sitemaps are enabled
4. Submit ` + "`https://yourdomain.com/sitemap_index.xml`" + ` to Google Search Console`,
		},
	}

	// -------------------------------------------------------------------------
	// 42. Robots.txt Quality
	// -------------------------------------------------------------------------
	RemediationDB["Robots.txt Quality"] = RemediationGuide{
		CheckName:    "Robots.txt Quality",
		Title:        "Configure Robots.txt Properly",
		Description:  "A well-configured robots.txt guides search engines on which pages to crawl and index, improving SEO and protecting private areas.",
		Priority:     "low",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Robots.txt is served from your origin server. Cloudflare passes it through without modification.`,

			"apache": `## Apache / Static Sites

Create ` + "`robots.txt`" + ` in your document root:

` + "```" + `
User-agent: *
Allow: /
Disallow: /admin/
Disallow: /private/
Disallow: /tmp/

Sitemap: https://yourdomain.com/sitemap.xml
` + "```" + `

**Best practices:**
- Do not block CSS/JS files (breaks rendering for crawlers)
- Always include a Sitemap directive
- Do not use robots.txt to hide sensitive URLs (use authentication instead)
- Test at [Google Robots Testing Tool](https://support.google.com/webmasters/answer/6062598)`,

			"nginx": `## Nginx / Static Sites

Create ` + "`robots.txt`" + ` in your document root. See Apache guide for content format.

Ensure Nginx serves it:

` + "```nginx" + `
location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
}
` + "```",

			"litespeed": `## LiteSpeed

Create ` + "`robots.txt`" + ` in your document root. LiteSpeed serves it automatically. See the Apache guide for best practices.`,

			"plesk": `## Plesk

1. Go to **Websites & Domains** > your domain > **SEO Toolkit** (if available)
2. Or create ` + "`robots.txt`" + ` manually via **File Manager** in the document root`,

			"cpanel": `## cPanel

1. Use **File Manager** to create ` + "`robots.txt`" + ` in ` + "`public_html`" + `
2. Follow the best practices in the Apache guide above`,

			"wordpress": `## WordPress - Robots.txt

WordPress generates a virtual ` + "`robots.txt`" + ` automatically. To customize:

**Option 1: SEO Plugin (Recommended)**

1. Install **Yoast SEO** or **Rank Math**
2. Go to **SEO** > **Tools** > **File Editor**
3. Edit ` + "`robots.txt`" + ` with custom rules

**Option 2: Physical file**

Create ` + "`robots.txt`" + ` in your WordPress root (overrides virtual):

` + "```" + `
User-agent: *
Allow: /
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php

Sitemap: https://yourdomain.com/sitemap_index.xml
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 43. Structured Data
	// -------------------------------------------------------------------------
	RemediationDB["Structured Data"] = RemediationGuide{
		CheckName:    "Structured Data",
		Title:        "Add Structured Data (JSON-LD Schema)",
		Description:  "Structured data helps search engines understand your content, enabling rich snippets in search results.",
		Priority:     "low",
		TimeEstimate: "20 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Structured data must be added to your HTML source. Cloudflare Workers can inject it dynamically if needed.`,

			"apache": `## Apache / Static Sites

Add JSON-LD structured data inside ` + "`<head>`" + ` or before ` + "`</body>`" + `:

` + "```html" + `
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "Your Organization",
  "url": "https://yourdomain.com",
  "logo": "https://yourdomain.com/logo.png",
  "contactPoint": {
    "@type": "ContactPoint",
    "telephone": "+1-XXX-XXX-XXXX",
    "contactType": "customer service"
  }
}
</script>
` + "```" + `

Validate at [Google Rich Results Test](https://search.google.com/test/rich-results)`,

			"nginx": `## Nginx / Static Sites

Add JSON-LD schema markup in your HTML source. See the Apache guide for the JSON-LD format.`,

			"litespeed": `## LiteSpeed

Structured data is added in HTML, not server config. See the Apache guide for JSON-LD format.`,

			"plesk": `## Plesk

Edit your HTML files to add JSON-LD structured data. See the Apache guide for examples.`,

			"cpanel": `## cPanel

Edit your HTML files via **File Manager** to add JSON-LD schema markup.`,

			"wordpress": `## WordPress - Structured Data

**Option 1: SEO Plugin (Recommended)**

**Yoast SEO** and **Rank Math** add structured data automatically:
1. Install and configure the plugin
2. Set your organization/person info in **SEO** > **Search Appearance**
3. The plugin generates JSON-LD for pages, posts, breadcrumbs, and more

**Option 2: Dedicated Schema Plugin**

Install **Schema Pro** or **WP Schema** for advanced schema types:
- FAQ schema
- How-to schema
- Product schema
- Event schema

**Option 3: Manual**

` + "```php" + `
add_action('wp_head', function() {
    if (is_front_page()) {
        echo '<script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","name":"' . get_bloginfo('name') . '","url":"' . home_url() . '"}
        </script>';
    }
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 44. Domain Reputation & Age
	// -------------------------------------------------------------------------
	RemediationDB["Domain Reputation & Age"] = RemediationGuide{
		CheckName:    "Domain Reputation & Age",
		Title:        "Improve Domain Reputation",
		Description:  "Domain age is fixed, but reputation can be improved through good practices. Poor reputation can affect email deliverability and search rankings.",
		Priority:     "low",
		TimeEstimate: "ongoing",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Domain Reputation

Cloudflare can help improve reputation:

1. Enable **Bot Fight Mode** to prevent abuse
2. Enable **DNSSEC** under **DNS** > **Settings**
3. Use **Email Routing** to set up proper email authentication
4. Ensure SPF, DKIM, and DMARC records are configured

> Domain reputation improves over time with consistent good practices.`,

			"apache": `## General - Improve Domain Reputation

**Technical measures:**
- Ensure SPF, DKIM, and DMARC DNS records are properly configured
- Enable HTTPS on all pages
- Set up proper HSTS headers
- Monitor blacklists: check [MXToolbox](https://mxtoolbox.com/blacklists.aspx)
- Remove malware or phishing content immediately

**Content measures:**
- Publish quality, original content regularly
- Avoid spammy SEO practices
- Get backlinks from reputable sites
- Register domain for multiple years (signals legitimacy)`,

			"nginx": `## General - Domain Reputation

Domain reputation is not server-specific. Follow general best practices:

1. Configure email authentication (SPF, DKIM, DMARC)
2. Keep site malware-free (use security scanning)
3. Monitor blacklists regularly
4. Maintain consistent uptime
5. Use HTTPS everywhere`,

			"litespeed": `## LiteSpeed

Domain reputation is managed through DNS and content practices, not server configuration. See the general guide above.`,

			"plesk": `## Plesk

1. Use **Security** > **SSL/TLS** to enforce HTTPS
2. Configure email authentication under **Mail** > **Mail Settings**
3. Enable DKIM signing for outgoing emails
4. Monitor domain health in **Websites & Domains**`,

			"cpanel": `## cPanel

1. Go to **Email** > **Authentication** to set up SPF and DKIM
2. Use **Security** > **SSL/TLS** to enforce HTTPS
3. Monitor email deliverability and blacklists
4. Keep all software updated to prevent compromise`,

			"wordpress": `## WordPress - Domain Reputation

1. Keep WordPress, themes, and plugins **updated**
2. Install a security plugin (**Wordfence** or **Sucuri**)
3. Run regular malware scans
4. Use **Google Search Console** to monitor for security issues
5. Ensure proper email authentication (SPF, DKIM, DMARC at DNS level)
6. Submit sitemap to search engines
7. Build quality backlinks through good content`,
		},
	}

	// -------------------------------------------------------------------------
	// 45. Time to First Byte (TTFB)
	// -------------------------------------------------------------------------
	RemediationDB["Time to First Byte (TTFB)"] = RemediationGuide{
		CheckName:    "Time to First Byte (TTFB)",
		Title:        "Improve Time to First Byte (TTFB)",
		Description:  "TTFB measures the time from the request to the first byte of the response. High TTFB indicates server-side performance issues.",
		Priority:     "medium",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Improve TTFB

1. Enable **Caching** > set **Browser Cache TTL** to at least 4 hours
2. Enable **Tiered Cache** under **Caching** > **Tiered Cache**
3. Enable **Early Hints** under **Speed** > **Optimization**
4. Enable **0-RTT Connection Resumption** under **Network**
5. Create **Page Rules** to cache static HTML pages
6. Consider **Argo Smart Routing** (paid) for optimal routing`,

			"apache": `## Apache - Improve TTFB

**Enable caching modules:**

` + "```bash" + `
sudo a2enmod cache cache_disk expires headers
sudo systemctl restart apache2
` + "```" + `

**Add caching rules to ` + "`.htaccess`" + `:**

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/html "access plus 1 hour"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 year"
</IfModule>
` + "```" + `

**Other optimizations:**
- Enable ` + "`mod_php`" + ` opcode caching (OPcache)
- Use ` + "`KeepAlive On`" + ` with ` + "`MaxKeepAliveRequests 100`" + `
- Optimize database queries in your application`,

			"nginx": `## Nginx - Improve TTFB

**Enable FastCGI caching:**

` + "```nginx" + `
fastcgi_cache_path /tmp/nginx_cache levels=1:2 keys_zone=MYAPP:100m inactive=60m;

server {
    fastcgi_cache MYAPP;
    fastcgi_cache_valid 200 60m;
    fastcgi_cache_use_stale error timeout updating;
    add_header X-Cache-Status $upstream_cache_status;
}
` + "```" + `

**Enable connection keepalive:**

` + "```nginx" + `
keepalive_timeout 65;
keepalive_requests 100;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Improve TTFB

1. Enable **LiteSpeed Cache** in Admin Console
2. Go to **Server** > **Cache** > enable **Page Cache**
3. Set **Cache TTL** to at least 3600 seconds
4. Enable **Object Cache** if using Redis/Memcached
5. LiteSpeed's built-in caching is highly efficient - TTFB improvements are often significant`,

			"plesk": `## Plesk - Improve TTFB

1. Enable **nginx caching**: Domains > your domain > **Apache & nginx Settings** > check **Proxy mode**
2. Enable **OPcache** for PHP: **PHP Settings** > ensure OPcache is enabled
3. Increase PHP memory limit if needed
4. Consider enabling Redis/Memcached for object caching`,

			"cpanel": `## cPanel - Improve TTFB

1. Go to **Software** > **Select PHP Version**
2. Enable **OPcache** extension
3. Increase **memory_limit** to at least 256M
4. Go to **Software** > **Optimize Website** > enable compression
5. Consider upgrading to LiteSpeed if available from your host`,

			"wordpress": `## WordPress - Improve TTFB

**Caching (most impactful):**
1. Install **LiteSpeed Cache**, **WP Super Cache**, or **W3 Total Cache**
2. Enable page caching and object caching

**Database:**
1. Install **WP-Optimize** to clean up database
2. Remove unused plugins and themes
3. Limit post revisions in ` + "`wp-config.php`" + `:
   ` + "`define('WP_POST_REVISIONS', 5);`" + `

**PHP:**
1. Use PHP 8.0+ (ask your host to upgrade)
2. Increase memory: ` + "`define('WP_MEMORY_LIMIT', '256M');`" + ` in ` + "`wp-config.php`" + `

**Hosting:**
Consider upgrading from shared hosting to VPS or managed WordPress hosting.`,
		},
	}

	// -------------------------------------------------------------------------
	// 46. Content-Type & X-XSS-Protection Headers
	// -------------------------------------------------------------------------
	RemediationDB["Content-Type & X-XSS-Protection Headers"] = RemediationGuide{
		CheckName:    "Content-Type & X-XSS-Protection Headers",
		Title:        "Set Content-Type and X-XSS-Protection Headers",
		Description:  "Proper Content-Type prevents MIME sniffing attacks. X-XSS-Protection enables browser-level XSS filtering.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Content-Type & XSS Headers

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add headers:
   - ` + "`X-Content-Type-Options: nosniff`" + `
   - ` + "`X-XSS-Protection: 1; mode=block`" + `

> ` + "`X-Content-Type-Options`" + ` is often more important than ` + "`X-XSS-Protection`" + `. Modern browsers rely on CSP instead of XSS-Protection.`,

			"apache": `## Apache - Content-Type & XSS Headers

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>

# Ensure proper Content-Type for common file types
AddType text/html .html .htm
AddType text/css .css
AddType application/javascript .js
AddType application/json .json
` + "```",

			"nginx": `## Nginx - Content-Type & XSS Headers

Add inside your ` + "`server`" + ` block:

` + "```nginx" + `
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
` + "```" + `

Ensure MIME types are configured in ` + "`/etc/nginx/mime.types`" + `.

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Content-Type & XSS Headers

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
` + "```",

			"plesk": `## Plesk - Content-Type & XSS Headers

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
` + "```" + `

3. Click **Apply**`,

			"cpanel": `## cPanel - Content-Type & XSS Headers

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Content-Type & XSS Headers

` + "```php" + `
add_action('send_headers', function() {
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
});
` + "```" + `

Or use the **HTTP Headers** plugin for a no-code solution.

> Modern best practice: also add a strong **Content-Security-Policy** header, which provides better XSS protection than X-XSS-Protection.`,
		},
	}

	// -------------------------------------------------------------------------
	// 47. Environment File Exposure
	// -------------------------------------------------------------------------
	RemediationDB["Environment File Exposure"] = RemediationGuide{
		CheckName:    "Environment File Exposure",
		Title:        "Block Access to .env Files",
		Description:  "Exposed .env files leak database credentials, API keys, and other secrets. This is a critical security vulnerability.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block .env Access

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path contains \"/.env\")`" + `
   - **Action**: Block
3. Deploy

Or use a **Transform Rule** to return 403 for .env requests.`,

			"apache": `## Apache - Block .env Access

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
# Block access to .env files
<FilesMatch "^\.env">
    Require all denied
</FilesMatch>
` + "```" + `

**Also remove the file from web root:**

` + "```bash" + `
# Move .env above document root (recommended)
mv /var/www/html/.env /var/www/.env
` + "```" + `

> **Critical**: If .env was publicly accessible, rotate ALL credentials in it immediately.`,

			"nginx": `## Nginx - Block .env Access

Add to your ` + "`server`" + ` block:

` + "```nginx" + `
# Block access to dotenv files
location ~ /\.env {
    deny all;
    return 404;
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + `

> **Critical**: If exposed, rotate all credentials in the .env file immediately.`,

			"litespeed": `## LiteSpeed - Block .env Access

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "^\.env">
    Require all denied
</FilesMatch>
` + "```" + `

Or use LiteSpeed Admin > **Security** to block the pattern.`,

			"plesk": `## Plesk - Block .env Access

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:

` + "```apache" + `
<FilesMatch "^\.env">
    Require all denied
</FilesMatch>
` + "```" + `

3. Click **Apply**
4. Remove or move the .env file outside the web root`,

			"cpanel": `## cPanel - Block .env Access

1. Open **File Manager** > edit ` + "`" + `.htaccess` + "`" + `
2. Add:

` + "```apache" + `
<FilesMatch "^\.env">
    Require all denied
</FilesMatch>
` + "```" + `

3. Move the ` + "`.env`" + ` file above ` + "`public_html`" + ` if possible
4. **Rotate all credentials** if the file was publicly accessible`,

			"wordpress": `## WordPress - Block .env Access

Add to ` + "`" + `.htaccess` + "`" + ` (before WordPress rules):

` + "```apache" + `
<FilesMatch "^\.env">
    Require all denied
</FilesMatch>
` + "```" + `

**Critical steps:**
1. Move ` + "`.env`" + ` above the WordPress root directory
2. If it was exposed, **immediately rotate** all database passwords, API keys, and secrets
3. Check server logs for unauthorized access to the file`,
		},
	}

	// -------------------------------------------------------------------------
	// 48. Git Repository Exposure
	// -------------------------------------------------------------------------
	RemediationDB["Git Repository Exposure"] = RemediationGuide{
		CheckName:    "Git Repository Exposure",
		Title:        "Block Access to .git Directory",
		Description:  "An exposed .git directory lets attackers download your entire source code, commit history, and potentially secrets.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block .git Access

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path contains \"/.git\")`" + `
   - **Action**: Block
3. Deploy`,

			"apache": `## Apache - Block .git Access

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
# Block access to .git directory
RedirectMatch 404 /\.git

# Alternative: deny all
<DirectoryMatch "^/.*/\.git/">
    Require all denied
</DirectoryMatch>
` + "```" + `

**Better solution**: Remove .git from production:

` + "```bash" + `
rm -rf /var/www/html/.git
` + "```" + `

> Deploy using CI/CD instead of ` + "`git pull`" + ` on production servers.`,

			"nginx": `## Nginx - Block .git Access

Add to your ` + "`server`" + ` block:

` + "```nginx" + `
# Block all dotfile directories
location ~ /\.git {
    deny all;
    return 404;
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + `

**Best practice**: Remove ` + "`.git`" + ` from production entirely and use CI/CD for deployments.`,

			"litespeed": `## LiteSpeed - Block .git Access

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RedirectMatch 404 /\.git
` + "```" + `

Or remove ` + "`.git`" + ` from the web root entirely.`,

			"plesk": `## Plesk - Block .git Access

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Add to **Additional Apache directives**:
   ` + "`RedirectMatch 404 /\\.git`" + `
3. Click **Apply**
4. Remove ` + "`.git`" + ` directory from the web root if present`,

			"cpanel": `## cPanel - Block .git Access

1. Edit ` + "`" + `.htaccess` + "`" + ` via **File Manager**:

` + "```apache" + `
RedirectMatch 404 /\.git
` + "```" + `

2. Delete the ` + "`.git`" + ` folder from ` + "`public_html`" + ` if it exists
3. Use deploy scripts or CI/CD instead of ` + "`git clone`" + ` in production`,

			"wordpress": `## WordPress - Block .git Access

Add to ` + "`" + `.htaccess` + "`" + ` (before WordPress rules):

` + "```apache" + `
RedirectMatch 404 /\.git
` + "```" + `

**Important:**
1. Remove ` + "`.git`" + ` from your WordPress directory: ` + "`rm -rf .git`" + `
2. Never deploy WordPress via ` + "`git clone`" + ` to production
3. If exposed, review commit history for leaked secrets and rotate them`,
		},
	}

	// -------------------------------------------------------------------------
	// 49. PHP Info Exposure
	// -------------------------------------------------------------------------
	RemediationDB["PHP Info Exposure"] = RemediationGuide{
		CheckName:    "PHP Info Exposure",
		Title:        "Remove or Block phpinfo() Files",
		Description:  "phpinfo() exposes PHP version, modules, environment variables, and server paths, giving attackers valuable reconnaissance data.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block phpinfo Access

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path contains \"phpinfo\")`" + `
   - **Action**: Block
3. Deploy`,

			"apache": `## Apache - Remove phpinfo

**Step 1: Delete the file:**

` + "```bash" + `
find /var/www -name "phpinfo.php" -delete
find /var/www -name "info.php" -delete
` + "```" + `

**Step 2: Block future access via .htaccess:**

` + "```apache" + `
<FilesMatch "phpinfo\.php|info\.php">
    Require all denied
</FilesMatch>
` + "```" + `

**Step 3: Disable in PHP config (` + "`php.ini`" + `):**

` + "```ini" + `
disable_functions = phpinfo
` + "```",

			"nginx": `## Nginx - Block phpinfo

**Delete the file:**

` + "```bash" + `
find /var/www -name "phpinfo.php" -delete
` + "```" + `

**Block via Nginx:**

` + "```nginx" + `
location ~* phpinfo\.php$ {
    deny all;
    return 404;
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Remove phpinfo

1. Delete ` + "`phpinfo.php`" + ` from your document root
2. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "phpinfo\.php|info\.php">
    Require all denied
</FilesMatch>
` + "```" + `

3. Disable in PHP: add ` + "`phpinfo`" + ` to ` + "`disable_functions`" + ` in php.ini`,

			"plesk": `## Plesk - Remove phpinfo

1. Use **File Manager** to find and delete ` + "`phpinfo.php`" + `
2. Go to **PHP Settings** for your domain
3. Add ` + "`phpinfo`" + ` to **disable_functions**
4. Click **Apply**`,

			"cpanel": `## cPanel - Remove phpinfo

1. Open **File Manager** > search for ` + "`phpinfo.php`" + `
2. Delete all instances found
3. Go to **Software** > **MultiPHP INI Editor**
4. Add ` + "`phpinfo`" + ` to ` + "`disable_functions`" + `
5. Save changes`,

			"wordpress": `## WordPress - Remove phpinfo

1. Search and delete any ` + "`phpinfo.php`" + ` file in your WordPress directory
2. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "phpinfo\.php|info\.php">
    Require all denied
</FilesMatch>
` + "```" + `

3. WordPress does not need phpinfo - it should never exist in production`,
		},
	}

	// -------------------------------------------------------------------------
	// 50. Htaccess File Exposure
	// -------------------------------------------------------------------------
	RemediationDB["Htaccess File Exposure"] = RemediationGuide{
		CheckName:    "Htaccess File Exposure",
		Title:        "Block Access to .htaccess File",
		Description:  "An exposed .htaccess file reveals server configuration, rewrite rules, and potentially authentication details.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block .htaccess Access

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path contains \".htaccess\")`" + `
   - **Action**: Block
3. Deploy`,

			"apache": `## Apache - Block .htaccess Access

Apache should block .htaccess by default. Verify your config includes:

` + "```apache" + `
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
` + "```" + `

If ` + "`.htaccess`" + ` is accessible, check ` + "`/etc/apache2/apache2.conf`" + ` for:

` + "```apache" + `
<Directory />
    AllowOverride None
    <FilesMatch "^\.ht">
        Require all denied
    </FilesMatch>
</Directory>
` + "```" + `

Restart: ` + "`sudo systemctl restart apache2`" + ``,

			"nginx": `## Nginx - Block .htaccess Access

Nginx does not use .htaccess, but the file may still be in the document root. Block it:

` + "```nginx" + `
location ~ /\.ht {
    deny all;
    return 404;
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Block .htaccess Access

LiteSpeed should block this by default. Verify by adding to your virtual host config:

` + "```apache" + `
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
` + "```",

			"plesk": `## Plesk - Block .htaccess Access

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Verify that dotfile access is blocked
3. Add to **Additional nginx directives**:
   ` + "`location ~ /\\.ht { deny all; return 404; }`" + `
4. Click **Apply**`,

			"cpanel": `## cPanel - Block .htaccess Access

Apache on cPanel should block .htaccess access by default. If it is exposed:

1. Contact your hosting provider - this is a server misconfiguration
2. Verify the main Apache config includes:
   ` + "`<FilesMatch \"^\\.ht\"> Require all denied </FilesMatch>`" + ``,

			"wordpress": `## WordPress - Block .htaccess Access

WordPress relies on .htaccess but it should never be downloadable. Verify protection:

Add at the **top** of ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
` + "```" + `

If your host's Apache does not block this by default, contact them to fix the server configuration.`,
		},
	}

	// -------------------------------------------------------------------------
	// 51. WordPress Config Backup
	// -------------------------------------------------------------------------
	RemediationDB["WordPress Config Backup"] = RemediationGuide{
		CheckName:    "WordPress Config Backup",
		Title:        "Remove WordPress Config Backup Files",
		Description:  "Backup copies of wp-config.php (like wp-config.php.bak) expose database credentials, secret keys, and other sensitive settings.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block Config Backup Access

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path contains \"wp-config\" and not http.request.uri.path eq \"/wp-config.php\")`" + `
   - **Action**: Block
3. Deploy

> This blocks .bak, .old, .save, .swp variants while allowing the real wp-config.php (which PHP processes, not downloads).`,

			"apache": `## Apache - Remove Config Backups

**Step 1: Delete backup files:**

` + "```bash" + `
rm -f /var/www/html/wp-config.php.bak
rm -f /var/www/html/wp-config.php.old
rm -f /var/www/html/wp-config.php.save
rm -f /var/www/html/wp-config.php~
rm -f /var/www/html/wp-config.php.swp
` + "```" + `

**Step 2: Block access via .htaccess:**

` + "```apache" + `
<FilesMatch "wp-config\.php\.(bak|old|save|swp|txt)|wp-config\.php~">
    Require all denied
</FilesMatch>
` + "```",

			"nginx": `## Nginx - Block Config Backups

**Delete files:**

` + "```bash" + `
rm -f /var/www/html/wp-config.php.bak /var/www/html/wp-config.php.old
` + "```" + `

**Block access:**

` + "```nginx" + `
location ~* wp-config\.php\.(bak|old|save|swp|txt)$ {
    deny all;
    return 404;
}
location ~* wp-config\.php~$ {
    deny all;
    return 404;
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Remove Config Backups

1. Delete all backup files: ` + "`rm -f wp-config.php.bak wp-config.php.old wp-config.php~`" + `
2. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "wp-config\.php\.(bak|old|save|swp|txt)|wp-config\.php~">
    Require all denied
</FilesMatch>
` + "```",

			"plesk": `## Plesk - Remove Config Backups

1. Use **File Manager** to find and delete all ` + "`wp-config.php.*`" + ` backup files
2. Add to Apache directives:

` + "```apache" + `
<FilesMatch "wp-config\.php\.(bak|old|save|swp|txt)|wp-config\.php~">
    Require all denied
</FilesMatch>
` + "```",

			"cpanel": `## cPanel - Remove Config Backups

1. Open **File Manager** > navigate to WordPress root
2. Delete ` + "`wp-config.php.bak`" + `, ` + "`wp-config.php.old`" + `, and similar files
3. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "wp-config\.php\.(bak|old|save|swp|txt)|wp-config\.php~">
    Require all denied
</FilesMatch>
` + "```",

			"wordpress": `## WordPress - Remove Config Backups

**Immediate actions:**
1. Delete all backup files:

` + "```bash" + `
rm -f wp-config.php.bak wp-config.php.old wp-config.php.save wp-config.php~ wp-config.php.swp
` + "```" + `

2. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "wp-config\.php\.(bak|old|save|swp|txt)|wp-config\.php~">
    Require all denied
</FilesMatch>
` + "```" + `

3. **Rotate all credentials** in wp-config.php if the backup was publicly accessible
4. Generate new secret keys at [WordPress Salt Generator](https://api.wordpress.org/secret-key/1.1/salt/)`,
		},
	}

	// -------------------------------------------------------------------------
	// 52. Backup Directory Exposure
	// -------------------------------------------------------------------------
	RemediationDB["Backup Directory Exposure"] = RemediationGuide{
		CheckName:    "Backup Directory Exposure",
		Title:        "Block Access to Backup Directories",
		Description:  "Exposed backup directories can contain database dumps, full site archives, and configuration files with credentials.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block Backup Access

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path contains \"/backup\") or (http.request.uri.path contains \"/backups\")`" + `
   - **Action**: Block
3. Deploy`,

			"apache": `## Apache - Block Backup Access

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
# Block backup directories
<DirectoryMatch "(backup|backups|bak|old|archive)">
    Require all denied
</DirectoryMatch>

# Block backup file extensions
<FilesMatch "\.(sql|gz|tar|zip|bak|old|dump)$">
    Require all denied
</FilesMatch>
` + "```" + `

**Best practice**: Move backups outside the web root:

` + "```bash" + `
mv /var/www/html/backup /var/backups/site-backup
` + "```",

			"nginx": `## Nginx - Block Backup Access

` + "```nginx" + `
# Block backup directories
location ~* /(backup|backups|bak|old|archive)/ {
    deny all;
    return 404;
}

# Block backup file types
location ~* \.(sql|gz|tar|zip|bak|dump)$ {
    deny all;
    return 404;
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Block Backup Access

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<DirectoryMatch "(backup|backups|bak)">
    Require all denied
</DirectoryMatch>
<FilesMatch "\.(sql|gz|tar|zip|bak|dump)$">
    Require all denied
</FilesMatch>
` + "```" + `

Move backups outside the document root.`,

			"plesk": `## Plesk - Block Backup Access

1. Use **File Manager** to move or delete backup directories from the web root
2. Plesk stores its own backups in ` + "`/var/lib/psa/dumps`" + ` (not web-accessible)
3. Add to Apache directives to block backup access:
   ` + "`<FilesMatch \"\\.(sql|gz|tar|zip|bak|dump)$\"> Require all denied </FilesMatch>`" + ``,

			"cpanel": `## cPanel - Block Backup Access

1. Move backups out of ` + "`public_html`" + `:
   - Use **File Manager** to move backup files/folders to ` + "`/home/user/backups/`" + `
2. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<FilesMatch "\.(sql|gz|tar|zip|bak|dump)$">
    Require all denied
</FilesMatch>
` + "```" + `

3. Use cPanel's built-in backup feature instead of storing backups in web root`,

			"wordpress": `## WordPress - Block Backup Access

1. Delete or move backup directories from WordPress root:

` + "```bash" + `
mv backup/ /var/backups/wordpress-backup/
` + "```" + `

2. Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<DirectoryMatch "(backup|backups|bak)">
    Require all denied
</DirectoryMatch>
<FilesMatch "\.(sql|gz|tar|zip|bak|dump)$">
    Require all denied
</FilesMatch>
` + "```" + `

3. Use a backup plugin that stores files outside the web root (e.g., **UpdraftPlus** with remote storage)`,
		},
	}

	// -------------------------------------------------------------------------
	// 53. Server Status Exposure
	// -------------------------------------------------------------------------
	RemediationDB["Server Status Exposure"] = RemediationGuide{
		CheckName:    "Server Status Exposure",
		Title:        "Disable Server Status/Info Pages",
		Description:  "Apache's mod_status and mod_info pages expose server configuration, active connections, and performance data to attackers.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block Server Status

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`(http.request.uri.path eq \"/server-status\") or (http.request.uri.path eq \"/server-info\")`" + `
   - **Action**: Block
3. Deploy

> Also disable on the origin server to prevent direct-IP access.`,

			"apache": `## Apache - Disable Server Status

**Option 1: Disable the module:**

` + "```bash" + `
sudo a2dismod status
sudo systemctl restart apache2
` + "```" + `

**Option 2: Restrict access (if you need it locally):**

` + "```apache" + `
<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1
    Require ip ::1
</Location>
<Location "/server-info">
    SetHandler server-info
    Require ip 127.0.0.1
</Location>
` + "```" + `

**Option 3: Block via .htaccess:**

` + "```apache" + `
<Location "/server-status">
    Require all denied
</Location>
` + "```",

			"nginx": `## Nginx - Disable Status Page

If ` + "`stub_status`" + ` is enabled publicly, restrict it:

` + "```nginx" + `
location /nginx_status {
    stub_status;
    allow 127.0.0.1;
    deny all;
}

# Block Apache-style status URLs
location = /server-status { return 404; }
location = /server-info { return 404; }
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"litespeed": `## LiteSpeed - Disable Server Status

1. Go to **LiteSpeed Admin** > **Server** > **General**
2. Set **Server Status** to **Disabled** (or restrict to localhost)
3. Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Location "/server-status">
    Require all denied
</Location>
` + "```",

			"plesk": `## Plesk - Disable Server Status

1. Go to **Tools & Settings** > **Apache Web Server**
2. Ensure ` + "`mod_status`" + ` is not enabled for public access
3. Add to **Additional Apache directives** at server level:

` + "```apache" + `
<Location "/server-status">
    Require ip 127.0.0.1
</Location>
` + "```",

			"cpanel": `## cPanel - Disable Server Status

1. Access **WHM** > **Service Configuration** > **Apache Configuration**
2. Go to **Global Configuration**
3. Ensure ` + "`mod_status`" + ` is restricted
4. Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Location "/server-status">
    Require all denied
</Location>
` + "```",

			"wordpress": `## WordPress - Block Server Status

Add to ` + "`" + `.htaccess` + "`" + ` (before WordPress rules):

` + "```apache" + `
<Location "/server-status">
    Require all denied
</Location>
<Location "/server-info">
    Require all denied
</Location>
` + "```" + `

This is a server-level issue. If you are on shared hosting, contact your host to restrict ` + "`mod_status`" + ` access.`,
		},
	}

	// -------------------------------------------------------------------------
	// 54. SQL Injection Test
	// -------------------------------------------------------------------------
	RemediationDB["SQL Injection Test"] = RemediationGuide{
		CheckName:    "SQL Injection Test",
		Title:        "Prevent SQL Injection Attacks",
		Description:  "SQL Injection allows attackers to execute arbitrary SQL commands on your database, potentially reading, modifying, or deleting all data.",
		Priority:     "critical",
		TimeEstimate: "2 hours",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - SQL Injection Protection

1. Go to **Security** > **WAF**
2. Enable **Managed Rules**
3. Ensure the **Cloudflare OWASP Core Ruleset** is enabled
4. Under **OWASP ModSecurity**, verify SQL Injection rules are active:
   - Rule group: **SQL Injection**
   - Action: **Block**
5. Go to **Security** > **WAF** > **Custom Rules**
6. Create a rule to block common SQLi patterns:
   - Field: **URI Query String**
   - Operator: **contains**
   - Values: ` + "`UNION SELECT`" + `, ` + "`OR 1=1`" + `, ` + "`' OR '`" + `
   - Action: **Block**

> Cloudflare WAF provides an additional layer, but always fix the underlying code.`,

			"apache": `## Apache - SQL Injection Protection

**Enable ModSecurity WAF:**

` + "```bash" + `
sudo apt install libapache2-mod-security2
sudo a2enmod security2
` + "```" + `

**Configure OWASP rules in** ` + "`/etc/modsecurity/modsecurity.conf`" + `:

` + "```apache" + `
SecRuleEngine On
SecRule ARGS "@detectSQLi" "id:1,phase:2,deny,status:403,msg:'SQL Injection Detected'"
` + "```" + `

**In your application code:**

` + "```" + `
# WRONG - vulnerable to SQLi
query = "SELECT * FROM users WHERE id = " + user_input

# CORRECT - use parameterized queries
query = "SELECT * FROM users WHERE id = ?"
db.execute(query, [user_input])
` + "```" + `

Restart Apache: ` + "`sudo systemctl restart apache2`" + ``,

			"nginx": `## Nginx - SQL Injection Protection

**Install ModSecurity for Nginx:**

` + "```bash" + `
sudo apt install libnginx-mod-http-modsecurity
` + "```" + `

**Enable in** ` + "`nginx.conf`" + `:

` + "```nginx" + `
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
` + "```" + `

**Add SQLi blocking rules:**

` + "```nginx" + `
# Block common SQL injection patterns in query strings
if ($query_string ~* "(union.*select|insert.*into|delete.*from|drop.*table|update.*set)") {
    return 403;
}
` + "```" + `

**In your application code, always use parameterized queries and prepared statements.**

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"wordpress": `## WordPress - SQL Injection Protection

**Use WordPress prepared statements:**

` + "```php" + `
// WRONG - vulnerable
$wpdb->query("SELECT * FROM $wpdb->posts WHERE ID = $id");

// CORRECT - use $wpdb->prepare()
$wpdb->get_results($wpdb->prepare(
    "SELECT * FROM %i WHERE ID = %d",
    $wpdb->posts,
    $id
));
` + "```" + `

**Additional protections:**

1. Install a security plugin: **Wordfence** or **Sucuri Security**
2. Keep WordPress, themes, and plugins updated
3. Use ` + "`esc_sql()`" + ` for any custom SQL queries
4. Validate and sanitize all user input with ` + "`sanitize_text_field()`" + `, ` + "`intval()`" + `
5. Never use ` + "`$_GET`" + ` or ` + "`$_POST`" + ` directly in SQL queries`,

			"cpanel": `## cPanel - SQL Injection Protection

**Enable ModSecurity in WHM:**

1. Go to **WHM** > **Security Center** > **ModSecurity Configuration**
2. Set **ModSecurity** to **On**
3. Go to **ModSecurity Vendors**
4. Enable **OWASP ModSecurity Core Rule Set**
5. Click **Update** to fetch latest rules

**In cPanel:**

1. Go to **Security** > **ModSecurity**
2. Verify it is enabled for your domain
3. Check logs at **Metrics** > **Errors** for blocked requests

**In your application code:**
- Always use parameterized queries / prepared statements
- Never concatenate user input directly into SQL strings
- Use ORM frameworks when possible`,
		},
	}

	// -------------------------------------------------------------------------
	// 55. Database Error Disclosure
	// -------------------------------------------------------------------------
	RemediationDB["Database Error Disclosure"] = RemediationGuide{
		CheckName:    "Database Error Disclosure",
		Title:        "Hide Database Error Messages from Users",
		Description:  "Detailed database error messages expose table names, query structures, and database versions to attackers, making SQL injection and other attacks easier.",
		Priority:     "high",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Hide Database Errors

Cloudflare can mask error pages:

1. Go to **Rules** > **Configuration Rules**
2. Create a rule targeting your error pages
3. Under **Custom Pages**, configure:
   - **500-class errors**: Use a custom error page
4. Go to **Custom Pages** (Account level)
5. Upload a generic error page for **500 Internal Server Error**
6. This prevents raw database errors from reaching visitors

> Always fix the underlying application code — Cloudflare is an additional safety net.`,

			"apache": `## Apache - Hide Database Errors

**Disable detailed errors in production:**

` + "```apache" + `
# In .htaccess or virtual host config
php_flag display_errors Off
php_value error_reporting 0
ErrorDocument 500 /error-pages/500.html
ErrorDocument 503 /error-pages/503.html
` + "```" + `

**In PHP configuration (` + "`php.ini`" + `):**

` + "```ini" + `
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log
error_reporting = E_ALL
` + "```" + `

**Custom error page:**

` + "```apache" + `
<IfModule mod_rewrite.c>
    ErrorDocument 500 "An error occurred. Please try again later."
</IfModule>
` + "```" + `

Restart: ` + "`sudo systemctl restart apache2`" + ``,

			"nginx": `## Nginx - Hide Database Errors

**Configure custom error pages:**

` + "```nginx" + `
server {
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /var/www/error-pages;
        internal;
    }
}
` + "```" + `

**In your PHP configuration (` + "`php.ini`" + `):**

` + "```ini" + `
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log
` + "```" + `

**For FastCGI/PHP-FPM, ensure:**

` + "```nginx" + `
fastcgi_intercept_errors on;
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"wordpress": `## WordPress - Hide Database Errors

**In** ` + "`wp-config.php`" + `:

` + "```php" + `
// Disable debug mode in production
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', true); // Logs to wp-content/debug.log

// Disable database error display
$wpdb->hide_errors();
$wpdb->suppress_errors();
` + "```" + `

**Additional steps:**

1. Remove or protect ` + "`wp-content/debug.log`" + ` from public access
2. Add to ` + "`.htaccess`" + `:

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```" + `

3. Install a security plugin to handle error pages gracefully`,

			"cpanel": `## cPanel - Hide Database Errors

**Configure PHP error display:**

1. Go to **Software** > **MultiPHP INI Editor**
2. Select your domain
3. Set:
   - **display_errors**: Off
   - **log_errors**: On
4. Click **Apply**

**Set custom error pages:**

1. Go to **Advanced** > **Error Pages**
2. Select your domain
3. Customize the **500 Internal Server Error** page
4. Replace with a user-friendly message (no technical details)

**In your application code:**
- Use try/catch blocks around database operations
- Log detailed errors to files, never display to users
- Return generic error messages in responses`,
		},
	}

	// -------------------------------------------------------------------------
	// 56. Open Port Detection
	// -------------------------------------------------------------------------
	RemediationDB["Open Port Detection"] = RemediationGuide{
		CheckName:    "Open Port Detection",
		Title:        "Close Unnecessary Open Ports",
		Description:  "Open ports expose services to the internet. Unnecessary open ports increase the attack surface and can be exploited to gain unauthorized access.",
		Priority:     "high",
		TimeEstimate: "1 hour",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Port Protection

Cloudflare only proxies HTTP/HTTPS traffic by default, blocking access to non-standard ports:

1. Ensure your DNS records are **Proxied** (orange cloud)
2. Go to **Network** settings
3. Cloudflare proxies these ports by default:
   - HTTP: 80, 8080, 8880, 2052, 2082, 2086, 2095
   - HTTPS: 443, 2053, 2083, 2087, 2096, 8443
4. All other ports are blocked when traffic is proxied
5. For additional port access, use **Cloudflare Spectrum** (Enterprise)

> If your origin IP is exposed, Cloudflare cannot protect non-proxied ports. Restrict access at the firewall level.`,

			"apache": `## Apache / Linux Server - Close Open Ports

**Identify open ports:**

` + "```bash" + `
sudo ss -tlnp
sudo netstat -tlnp
` + "```" + `

**Close ports with UFW firewall:**

` + "```bash" + `
# Enable firewall
sudo ufw enable

# Allow only necessary ports
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 22/tcp    # SSH (restrict to your IP if possible)

# Deny everything else
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Block specific ports
sudo ufw deny 3306/tcp   # MySQL - should not be public
sudo ufw deny 5432/tcp   # PostgreSQL
sudo ufw deny 27017/tcp  # MongoDB

# Check status
sudo ufw status verbose
` + "```" + `

**With iptables:**

` + "```bash" + `
# Block MySQL from external access
sudo iptables -A INPUT -p tcp --dport 3306 -j DROP
sudo iptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1 -j ACCEPT
` + "```" + `

**Bind database to localhost in** ` + "`my.cnf`" + `:

` + "```ini" + `
[mysqld]
bind-address = 127.0.0.1
` + "```",

			"nginx": `## Nginx / Linux Server - Close Open Ports

**Audit open ports:**

` + "```bash" + `
sudo ss -tlnp
sudo nmap -sT localhost
` + "```" + `

**Configure UFW firewall:**

` + "```bash" + `
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 'Nginx Full'   # Allows 80 and 443
sudo ufw allow 22/tcp          # SSH

# Deny database ports from external access
sudo ufw deny 3306/tcp
sudo ufw deny 5432/tcp
sudo ufw deny 6379/tcp   # Redis
` + "```" + `

**Bind services to localhost:**

` + "```bash" + `
# Redis: /etc/redis/redis.conf
bind 127.0.0.1

# PostgreSQL: /etc/postgresql/*/main/postgresql.conf
listen_addresses = 'localhost'
` + "```" + `

Reload firewall: ` + "`sudo ufw reload`" + ``,

			"cpanel": `## cPanel - Close Open Ports

**Via WHM (root access required):**

1. Go to **WHM** > **Plugins** > **ConfigServer Security & Firewall (CSF)**
   - If not installed: ` + "`cd /usr/src && wget https://download.configserver.com/csf.tgz && tar -xzf csf.tgz && cd csf && sh install.sh`" + `
2. In CSF, go to **Firewall Configuration**
3. Edit **TCP_IN** to allow only needed ports:
   ` + "`" + `TCP_IN = "20,21,22,25,53,80,110,143,443,465,587,993,995,2077,2078,2082,2083,2086,2087,2095,2096"` + "`" + `
4. Edit **TCP_OUT** similarly
5. Click **Change** then **Restart csf+lfd**

**Block specific ports:**

1. In CSF, add to **Deny IP Addresses** for port-specific blocking
2. Or via command line:

` + "```bash" + `
csf -d IP_ADDRESS "Reason for block"
` + "```" + `

**Verify with:**

` + "```bash" + `
csf -p   # Show listening ports
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 57. Open Redirect Test
	// -------------------------------------------------------------------------
	RemediationDB["Open Redirect Test"] = RemediationGuide{
		CheckName:    "Open Redirect Test",
		Title:        "Fix Open Redirect Vulnerabilities",
		Description:  "Open redirects allow attackers to craft URLs on your domain that redirect users to malicious sites, enabling phishing attacks and credential theft.",
		Priority:     "medium",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"apache": `## Apache - Fix Open Redirects

**Block external redirects in** ` + "`.htaccess`" + `:

` + "```apache" + `
# Prevent open redirects via query parameters
RewriteEngine On
RewriteCond %{QUERY_STRING} (^|&)(url|redirect|next|return|goto)=https?:// [NC]
RewriteRule .* - [F,L]
` + "```" + `

**In your application code:**

` + "```" + `
# WRONG - open redirect
redirect_url = request.params["redirect"]
redirect(redirect_url)

# CORRECT - validate against whitelist
ALLOWED_HOSTS = ["yourdomain.com", "www.yourdomain.com"]
redirect_url = request.params["redirect"]
if parsed_url(redirect_url).host in ALLOWED_HOSTS:
    redirect(redirect_url)
else:
    redirect("/")  # fallback to homepage
` + "```" + `

**Best practices:**
- Use relative URLs for internal redirects (e.g., ` + "`/dashboard`" + ` instead of ` + "`https://yourdomain.com/dashboard`" + `)
- Never use user input directly in redirect targets
- Maintain a whitelist of allowed redirect domains`,

			"nginx": `## Nginx - Fix Open Redirects

**Block redirect parameters pointing externally:**

` + "```nginx" + `
# Block requests with external redirect URLs in query string
if ($query_string ~* "(redirect|url|next|return|goto)=https?://") {
    return 403;
}
` + "```" + `

**In your application code:**

- Validate all redirect URLs against a whitelist of allowed domains
- Use relative URLs (` + "`/path`" + `) instead of absolute URLs
- Strip or reject any redirect parameter containing ` + "`://`" + ` pointing to external domains
- Implement a safe redirect function:

` + "```" + `
func safeRedirect(targetURL, defaultURL string) string {
    parsed := parseURL(targetURL)
    if parsed.Host == "" || parsed.Host == "yourdomain.com" {
        return targetURL
    }
    return defaultURL
}
` + "```" + `

Reload: ` + "`sudo nginx -t && sudo systemctl reload nginx`" + ``,

			"wordpress": `## WordPress - Fix Open Redirects

**Use** ` + "`wp_safe_redirect()`" + ` **instead of** ` + "`wp_redirect()`" + `:

` + "```php" + `
// WRONG - allows open redirect
wp_redirect($_GET['redirect_to']);

// CORRECT - validates against allowed hosts
wp_safe_redirect($_GET['redirect_to']);
exit;
` + "```" + `

**Add allowed redirect hosts:**

` + "```php" + `
// In functions.php or a custom plugin
add_filter('allowed_redirect_hosts', function($hosts) {
    $hosts[] = 'yourdomain.com';
    $hosts[] = 'www.yourdomain.com';
    $hosts[] = 'subdomain.yourdomain.com';
    return $hosts;
});
` + "```" + `

**Additional steps:**

1. Audit all uses of ` + "`wp_redirect()`" + ` in themes and plugins
2. Replace with ` + "`wp_safe_redirect()`" + `
3. Review plugins that handle login redirects (e.g., after login forms)
4. Update WordPress and all plugins to latest versions`,
		},
	}

	// -------------------------------------------------------------------------
	// 58. DNS Zone Transfer
	// -------------------------------------------------------------------------
	RemediationDB["DNS Zone Transfer"] = RemediationGuide{
		CheckName:    "DNS Zone Transfer",
		Title:        "Restrict DNS Zone Transfers (AXFR)",
		Description:  "Unrestricted DNS zone transfers allow anyone to download a complete copy of your DNS records, revealing all subdomains, internal hosts, and network topology.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - DNS Zone Transfer Protection

Cloudflare does not allow zone transfers by default — your DNS is already protected.

**Verify your setup:**

1. Ensure your domain's nameservers point to Cloudflare:
   - e.g., ` + "`ns1.cloudflare.com`" + ` and ` + "`ns2.cloudflare.com`" + `
2. Go to **DNS** > **Records** to review all entries
3. Cloudflare blocks AXFR queries at the edge — no action needed

**If you previously used another DNS provider:**

1. Confirm old nameservers are no longer authoritative
2. Check that no legacy NS records point to servers that allow AXFR
3. Verify with: ` + "`dig AXFR yourdomain.com @old-nameserver`" + `

> Cloudflare's managed DNS inherently prevents zone transfer attacks.`,

			"cpanel": `## cPanel - Restrict DNS Zone Transfers

**Via WHM (root required):**

1. Go to **WHM** > **DNS Functions** > **Edit DNS Zone**
2. Select your domain
3. Verify zone configuration

**Restrict AXFR in BIND (named.conf):**

` + "```bash" + `
# Edit named.conf
sudo nano /etc/named.conf
` + "```" + `

**Add allow-transfer ACL:**

` + "```" + `
options {
    allow-transfer { none; };  // Deny all zone transfers by default
};

// For specific zones, allow only secondary nameservers:
zone "yourdomain.com" {
    type master;
    file "/var/named/yourdomain.com.db";
    allow-transfer { 192.168.1.2; 10.0.0.5; };  // Only your secondary NS
};
` + "```" + `

**Restart DNS service:**

` + "```bash" + `
sudo systemctl restart named
# or
sudo rndc reload
` + "```" + `

**Verify zone transfer is blocked:**

` + "```bash" + `
dig AXFR yourdomain.com @your-nameserver
# Should return "Transfer failed" or no results
` + "```" + `

**In WHM Tweak Settings:**
1. Go to **Server Configuration** > **Tweak Settings**
2. Under **Domains**, ensure **Allow zone transfers** is disabled or restricted to known IPs`,
		},
	}

	// -------------------------------------------------------------------------
	// 59. WAF Detection
	// -------------------------------------------------------------------------
	RemediationDB["WAF Detection"] = RemediationGuide{
		CheckName:    "WAF Detection",
		Title:        "Enable Web Application Firewall (WAF)",
		Description:  "A WAF protects your website from common web attacks such as SQL injection, XSS, and DDoS by filtering and monitoring HTTP traffic.",
		Priority:     "medium",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable and Configure WAF

**Enable Managed WAF Rules:**

1. Log in to **Cloudflare Dashboard**
2. Select your domain
3. Go to **Security** > **WAF**
4. Enable **Managed Rules**:
   - **Cloudflare Managed Ruleset**: Covers common vulnerabilities
   - **Cloudflare OWASP Core Ruleset**: Covers OWASP Top 10
5. Set sensitivity to **High** for maximum protection
6. Review and customize rule actions:
   - **Block**: For critical attack patterns
   - **Challenge**: For suspicious but not definitive patterns
   - **Log**: For monitoring before enforcement

**Create Custom WAF Rules:**

1. Go to **Security** > **WAF** > **Custom Rules**
2. Add rules for your application:
   - Block requests from known-bad user agents
   - Rate limit login endpoints
   - Block requests with malicious payloads
3. Set rule priority (lower number = higher priority)

**Monitor WAF Activity:**

1. Go to **Security** > **Events**
2. Review blocked and challenged requests
3. Adjust rules to reduce false positives`,

			"cpanel": `## cPanel - Enable ModSecurity WAF

**Enable ModSecurity via WHM:**

1. Go to **WHM** > **Security Center** > **ModSecurity Configuration**
2. Set **ModSecurity** to **On**
3. Set **Audit Log Level** to **Only log noteworthy transactions**

**Install OWASP Rule Set:**

1. Go to **WHM** > **Security Center** > **ModSecurity Vendors**
2. Click **Add Vendor**
3. Add the OWASP ModSecurity Core Rule Set URL
4. Enable the vendor and click **Save**

**Or install manually:**

` + "```bash" + `
# Download OWASP CRS
cd /etc/apache2/modsecurity.d/
git clone https://github.com/coreruleset/coreruleset.git
cp coreruleset/crs-setup.conf.example crs-setup.conf

# Include in Apache config
echo 'Include /etc/apache2/modsecurity.d/coreruleset/rules/*.conf' >> /etc/apache2/conf.d/modsec_vendor_configs/owasp.conf
` + "```" + `

**Per-domain configuration in cPanel:**

1. Go to **Security** > **ModSecurity**
2. Enable or disable per-domain as needed
3. Review logs at **Metrics** > **Errors** for false positives

**Restart Apache:**

` + "```bash" + `
sudo systemctl restart httpd
` + "```",
		},
	}
}
