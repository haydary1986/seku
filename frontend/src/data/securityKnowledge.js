/**
 * Security Knowledge Base
 * Contains detailed explanations of each security check,
 * what it means, and how attackers can exploit vulnerabilities.
 */

export const categoryInfo = {
  ssl: {
    title: 'SSL/TLS Encryption',
    description: 'SSL/TLS provides encrypted communication between the user\'s browser and the web server. Without it, all data (passwords, personal info) travels in plain text.',
    importance: 'critical',
    attackScenario: 'Without SSL, an attacker on the same network (e.g., public WiFi) can use tools like Wireshark to intercept all traffic between users and the server, capturing login credentials, session tokens, and personal data (Man-in-the-Middle attack).',
  },
  headers: {
    title: 'Security Headers',
    description: 'HTTP security headers instruct browsers to enable built-in security features that protect against common web attacks like XSS, clickjacking, and data injection.',
    importance: 'high',
    attackScenario: 'Missing security headers leave the website vulnerable to multiple attacks. For example, without X-Frame-Options, an attacker can embed the site in an iframe and trick users into clicking hidden buttons (clickjacking).',
  },
  cookies: {
    title: 'Cookie Security',
    description: 'Cookies store session data and authentication tokens. Insecure cookie configuration can allow attackers to steal user sessions.',
    importance: 'high',
    attackScenario: 'Cookies without the HttpOnly flag can be stolen via XSS attacks using JavaScript (document.cookie). Without the Secure flag, cookies are sent over unencrypted HTTP connections where they can be intercepted.',
  },
  server_info: {
    title: 'Server Information Exposure',
    description: 'Server headers and CMS detection reveal the technology stack used. This information helps attackers find known vulnerabilities specific to those technologies.',
    importance: 'medium',
    attackScenario: 'If the server reveals it runs "Apache 2.4.49", an attacker can search for CVE-2021-41773 (path traversal vulnerability) and exploit it directly. Similarly, knowing the CMS version helps attackers use automated exploit tools.',
  },
  directory: {
    title: 'Directory & Sensitive File Exposure',
    description: 'Sensitive files and directories (like .env, .git, admin panels) should never be publicly accessible. They often contain credentials, configuration data, or provide administrative access.',
    importance: 'critical',
    attackScenario: 'An exposed .env file reveals database credentials, API keys, and secrets. An exposed .git directory allows attackers to download the entire source code. An accessible admin panel can be brute-forced to gain full control of the website.',
  },
  performance: {
    title: 'Server Performance',
    description: 'Server response time, TTFB (Time to First Byte), and TLS handshake speed indicate server health and configuration quality. Poor performance can indicate misconfiguration or resource constraints.',
    importance: 'medium',
    attackScenario: 'Slow servers are more vulnerable to denial-of-service (DoS) attacks because they have fewer resources to handle malicious traffic. Poor performance can also indicate the server is already under stress or attack.',
  },
  ddos: {
    title: 'DDoS Protection',
    description: 'DDoS (Distributed Denial of Service) protection includes CDN services, Web Application Firewalls (WAF), and rate limiting that prevent attackers from overwhelming the server with traffic.',
    importance: 'critical',
    attackScenario: 'Without DDoS protection, an attacker can use botnets to send millions of requests to the server, making it completely unavailable. Without a WAF, attackers can freely send SQL injection, XSS, and other malicious payloads. Without rate limiting, attackers can brute-force login pages.',
  },
  cors: {
    title: 'CORS Configuration',
    description: 'Cross-Origin Resource Sharing (CORS) controls which external websites can access the server\'s resources. Misconfigured CORS can allow malicious websites to steal data from authenticated users.',
    importance: 'high',
    attackScenario: 'If CORS allows all origins (*) with credentials, an attacker can create a malicious website that makes requests to the vulnerable site using the victim\'s session cookies, stealing sensitive data or performing actions on their behalf (similar to CSRF attacks).',
  },
  http_methods: {
    title: 'HTTP Methods Security',
    description: 'HTTP methods like TRACE, DELETE, PUT should be disabled on production servers. Leaving dangerous methods enabled allows attackers to manipulate server resources.',
    importance: 'high',
    attackScenario: 'An attacker uses the TRACE method to perform Cross-Site Tracing (XST) attacks, stealing HTTP-only cookies. The PUT method can be used to upload malicious files directly to the server.',
  },
  dns: {
    title: 'DNS Security (SPF, DMARC, CAA)',
    description: 'DNS security records (SPF, DMARC, CAA) protect the domain from email spoofing and unauthorized certificate issuance.',
    importance: 'high',
    attackScenario: 'Without SPF/DMARC, an attacker sends phishing emails that appear to come from your domain (e.g., admin@youruniversity.edu.iq), tricking students and staff into revealing credentials or downloading malware.',
  },
  mixed_content: {
    title: 'Mixed Content',
    description: 'Mixed content occurs when an HTTPS page loads resources (scripts, images, forms) over insecure HTTP. This breaks the security guarantee of HTTPS.',
    importance: 'high',
    attackScenario: 'An attacker intercepts the HTTP-loaded script on the HTTPS page, injects malicious code that steals login credentials or redirects users to a phishing site. The user sees the padlock icon and trusts the page.',
  },
  info_disclosure: {
    title: 'Information Disclosure',
    description: 'Information disclosure occurs when the server reveals internal details like technology versions, file paths, error messages, or debug information that help attackers plan targeted attacks.',
    importance: 'medium',
    attackScenario: 'Error pages revealing "PHP 7.2.1" and "/var/www/html" paths allow attackers to search for specific CVEs for that PHP version and target the exact file system structure.',
  },
  hosting: {
    title: 'Hosting Quality',
    description: 'Evaluates the quality of web hosting infrastructure including HTTP/2, HTTP/3 (QUIC), Brotli compression, IPv6 support, Keep-Alive connections, and DNS resolution speed.',
    importance: 'high',
    attackScenario: 'Poor hosting infrastructure with HTTP/1.1 only, no compression, and slow DNS makes the site vulnerable to performance-based attacks and provides a degraded user experience. Lack of IPv6 excludes a growing portion of internet users.',
  },
  content: {
    title: 'Content Optimization',
    description: 'Evaluates content delivery optimization including caching headers, page size, and compression effectiveness. Proper caching reduces server load and improves page load speed.',
    importance: 'medium',
    attackScenario: 'Without proper cache headers, every request hits the origin server, making it easier to overwhelm with traffic. Large uncompressed pages waste bandwidth and increase load times, degrading user experience and SEO rankings.',
  },
  advanced_security: {
    title: 'Advanced Security Headers',
    description: 'Modern cross-origin isolation headers (COEP, COOP, CORP) and OCSP Stapling provide defense-in-depth against sophisticated attacks like Spectre, cross-origin data leaks, and certificate validation delays.',
    importance: 'medium',
    attackScenario: 'Without cross-origin isolation, a malicious iframe or popup can exploit Spectre-class vulnerabilities to read sensitive data from the victim\'s browsing context. Without OCSP Stapling, certificate revocation checks add latency and may fail silently.',
  },
  threat_intel: {
    title: 'Threat Intelligence',
    description: 'Advanced threat detection including cryptojacking resource abuse, Command & Control (C2) server communication, DNS blacklist checking, and domain age/reputation analysis via WHOIS/RDAP data.',
    importance: 'critical',
    attackScenario: 'Compromised sites may silently mine cryptocurrency using visitor CPU, communicate with C2 servers to receive attack commands, or be listed on blacklists indicating prior malicious activity. New or recently registered domains hosting important services may indicate domain hijacking.',
  },
  seo: {
    title: 'SEO & Technical Health',
    description: 'Evaluates search engine optimization and technical health indicators including meta tags, Open Graph, sitemap, robots.txt quality, structured data, and mobile friendliness.',
    importance: 'medium',
    attackScenario: 'Poor SEO configuration can lead to search engine de-indexing, content scraping, and phishing sites outranking the legitimate site. Missing canonical URLs allow duplicate content attacks.',
  },
  third_party: {
    title: 'Third-Party Scripts Risk',
    description: 'Assesses the risk of external JavaScript and CSS loaded from third-party sources. Checks script count, Subresource Integrity (SRI), source trustworthiness, and external CSS dependencies.',
    importance: 'high',
    attackScenario: 'Compromised third-party scripts (supply chain attacks) can steal user data, inject malware, or redirect users. The Magecart attacks on e-commerce sites were all via compromised third-party scripts.',
  },
  js_libraries: {
    title: 'JavaScript Library Vulnerabilities',
    description: 'Detects outdated JavaScript libraries with known security vulnerabilities (CVEs). Checks jQuery, Angular, Bootstrap, Lodash, Moment.js, Vue, React versions and inline script patterns.',
    importance: 'high',
    attackScenario: 'Outdated jQuery (< 3.5.0) has known XSS vulnerabilities (CVE-2020-11022). Attackers scan for sites using vulnerable library versions and exploit known CVEs automatically.',
  },
  malware: {
    title: 'Malware & Threats',
    description: 'Scans the website for malware indicators including malicious JavaScript, hidden iframes, cryptocurrency miners, suspicious redirects, and known malware signatures.',
    importance: 'critical',
    attackScenario: 'Hackers inject malicious JavaScript or hidden iframes into compromised websites to steal visitor credentials, install ransomware, mine cryptocurrency using visitor CPU, or redirect users to phishing sites. These attacks are often invisible to site administrators.',
  },
  sqli: {
    title: 'SQL Injection',
    description: 'SQL injection occurs when user input is inserted into SQL queries without proper sanitization, allowing attackers to manipulate database operations.',
    importance: 'critical',
    attackScenario: 'An attacker enters SQL code in a login form (e.g., \' OR 1=1 --) to bypass authentication, or uses UNION queries to extract sensitive data like passwords, credit card numbers, or personal information from the database.',
  },
  ports: {
    title: 'Open Ports',
    description: 'Open network ports expose services to the internet. Unnecessary open ports increase the attack surface and may expose vulnerable services.',
    importance: 'high',
    attackScenario: 'An attacker scans for open database ports (MySQL 3306, PostgreSQL 5432) and attempts to connect directly, brute-forcing credentials or exploiting known vulnerabilities in exposed services.',
  },
  open_redirect: {
    title: 'Open Redirect',
    description: 'Open redirect vulnerabilities allow attackers to redirect users from a trusted domain to a malicious website through URL parameter manipulation.',
    importance: 'medium',
    attackScenario: 'An attacker crafts a phishing link using the university\'s trusted domain (e.g., university.edu/redirect?url=evil.com) to trick users into visiting malicious sites, making the phishing attack appear legitimate.',
  },
  ssrf: {
    title: 'Server-Side Request Forgery',
    description: 'SSRF allows attackers to make the server send requests to internal resources, potentially accessing internal services, metadata APIs, or sensitive internal endpoints.',
    importance: 'critical',
    attackScenario: 'An attacker exploits a URL-fetching feature to access the cloud metadata API (169.254.169.254) and steal IAM credentials, or probes internal network services that are not exposed to the internet.',
  },
  email_security: {
    title: 'Email Security',
    description: 'Email security records (SPF, DKIM, DMARC, BIMI) protect against email spoofing and phishing attacks targeting the organization\'s domain.',
    importance: 'high',
    attackScenario: 'Without DKIM and DMARC, an attacker can send emails that appear to come from the university\'s domain, tricking students and staff into revealing credentials or downloading malware.',
  },
  waf: {
    title: 'Web Application Firewall',
    description: 'A WAF protects web applications by filtering and monitoring HTTP traffic, blocking common attacks like SQL injection, XSS, and DDoS.',
    importance: 'medium',
    attackScenario: 'Without a WAF, automated attack tools can freely probe the website for vulnerabilities, launch SQL injection attacks, and exploit known CVEs without any filtering layer.',
  },
  zone_transfer: {
    title: 'DNS Zone Transfer',
    description: 'DNS zone transfer (AXFR) allows replication of DNS records between nameservers. If unrestricted, it exposes the complete DNS zone including all subdomains and internal records.',
    importance: 'high',
    attackScenario: 'An attacker performs a zone transfer to discover all subdomains, including internal ones (admin.uni.edu, vpn.uni.edu, dev.uni.edu) and then targets these potentially less-secured systems.',
  },
}

export const checkExplanations = {
  // SSL Checks
  'HTTPS Enabled': {
    what: 'Checks if the website is accessible over HTTPS (encrypted connection).',
    risk: 'All data between users and the server is transmitted in plain text.',
    exploit: 'Attacker uses network sniffing tools (Wireshark, tcpdump) on shared networks to capture passwords, session cookies, and personal data.',
    fix: 'Install an SSL/TLS certificate. Free certificates are available from Let\'s Encrypt.',
  },
  'Certificate Validity': {
    what: 'Verifies that the SSL certificate is valid, not expired, and issued by a trusted authority.',
    risk: 'Expired or invalid certificates cause browser warnings and can indicate a compromised connection.',
    exploit: 'Attackers can perform Man-in-the-Middle attacks when users click through certificate warnings. Expired certificates may indicate poor security practices.',
    fix: 'Renew SSL certificates before expiry. Use automated renewal with certbot or similar tools.',
  },
  'TLS Version': {
    what: 'Checks which version of TLS protocol the server supports. TLS 1.3 is the latest and most secure.',
    risk: 'Older TLS versions (1.0, 1.1) have known vulnerabilities like BEAST, POODLE, and CRIME attacks.',
    exploit: 'Attacker forces a protocol downgrade to TLS 1.0 and exploits known vulnerabilities to decrypt traffic.',
    fix: 'Configure the server to support TLS 1.2+ only. Disable TLS 1.0 and 1.1 in server configuration.',
  },
  'HTTP to HTTPS Redirect': {
    what: 'Checks if HTTP requests are automatically redirected to HTTPS.',
    risk: 'Users accessing the site via HTTP send their first request unencrypted, exposing cookies and data.',
    exploit: 'Attacker intercepts the initial HTTP request before the redirect happens, stealing session cookies (SSL stripping attack using tools like sslstrip).',
    fix: 'Configure server to redirect all HTTP traffic to HTTPS. Enable HSTS header.',
  },

  // Header Checks
  'HSTS': {
    what: 'HTTP Strict Transport Security forces browsers to always use HTTPS for the domain.',
    risk: 'Without HSTS, browsers may send initial requests over HTTP, vulnerable to SSL stripping.',
    exploit: 'Attacker performs SSL stripping attack using tools like sslstrip, intercepting the HTTP-to-HTTPS redirect.',
    fix: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  },
  'Content Security Policy': {
    what: 'CSP tells the browser which sources of content (scripts, styles, images) are allowed to load.',
    risk: 'Without CSP, the browser will execute any script injected into the page.',
    exploit: 'Attacker injects malicious JavaScript via XSS that loads external scripts from attacker-controlled servers, stealing cookies and user data.',
    fix: 'Add a Content-Security-Policy header that restricts script sources to trusted domains only.',
  },
  'X-Frame-Options': {
    what: 'Prevents the website from being embedded in iframes on other domains.',
    risk: 'The site can be loaded inside a hidden iframe on a malicious page.',
    exploit: 'Attacker creates a page with the target site in a transparent iframe overlay. When users click what they think are normal buttons, they actually click on the hidden site (clickjacking).',
    fix: 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
  },
  'X-Content-Type-Options': {
    what: 'Prevents browsers from MIME-type sniffing, forcing them to respect the declared content type.',
    risk: 'Browser may interpret uploaded files as executable scripts.',
    exploit: 'Attacker uploads a file with .jpg extension but containing JavaScript. Without this header, the browser may execute it as a script.',
    fix: 'Add header: X-Content-Type-Options: nosniff',
  },
  'X-XSS-Protection': {
    what: 'Legacy browser XSS filter (modern browsers rely on CSP instead).',
    risk: 'Older browsers may not filter XSS attacks.',
    exploit: 'Simple reflected XSS attacks may succeed in older browsers without this protection.',
    fix: 'Add header: X-XSS-Protection: 1; mode=block',
  },
  'Referrer-Policy': {
    what: 'Controls how much referrer information is shared when navigating from your site to another.',
    risk: 'Sensitive URLs and parameters may be leaked to third-party sites.',
    exploit: 'If your site has URLs like /user/12345/settings, visiting an external link leaks this information to the third-party server.',
    fix: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
  },
  'Permissions-Policy': {
    what: 'Controls which browser features (camera, microphone, geolocation) can be used on the page.',
    risk: 'Injected scripts or iframes could access sensitive browser features.',
    exploit: 'Attacker injects code that accesses the user\'s camera or microphone through the compromised page.',
    fix: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },

  // DDoS Checks
  'CDN/DDoS Protection Service': {
    what: 'Checks if the website is protected by a CDN or DDoS mitigation service (Cloudflare, AWS Shield, etc.).',
    risk: 'The server\'s real IP is exposed and directly attackable without protection.',
    exploit: 'Attacker sends massive amounts of traffic directly to the server IP using tools like LOIC or botnets, overwhelming the server and making it unavailable to legitimate users.',
    fix: 'Deploy behind a CDN like Cloudflare (free tier available) or AWS CloudFront. This hides the real server IP and absorbs attack traffic.',
  },
  'Rate Limiting': {
    what: 'Checks if the server limits the number of requests from a single source.',
    risk: 'Without rate limiting, attackers can send unlimited requests.',
    exploit: 'Attacker uses automated tools to brute-force login pages (trying thousands of passwords per minute), enumerate users, or overwhelm the server with requests.',
    fix: 'Implement rate limiting at the reverse proxy (Nginx: limit_req) or application level. Typical: 100 requests/minute per IP.',
  },
  'Web Application Firewall (WAF)': {
    what: 'Checks if a WAF is filtering malicious requests before they reach the application.',
    risk: 'Malicious payloads (SQL injection, XSS) reach the application directly.',
    exploit: 'Attacker sends SQL injection payloads like \' OR 1=1-- in form fields. Without a WAF, these reach the database layer directly.',
    fix: 'Deploy a WAF (ModSecurity, Cloudflare WAF, AWS WAF). Configure rules to block common attack patterns.',
  },

  // CORS Checks
  'CORS Wildcard Origin': {
    what: 'Checks if the server allows requests from any origin (*).',
    risk: 'Any website can make requests to your API and read the responses.',
    exploit: 'Attacker creates evil-site.com with JavaScript that makes requests to your API. If the victim visits evil-site.com while logged into your site, the attacker can read sensitive API responses.',
    fix: 'Configure CORS to only allow specific trusted origins instead of wildcard (*).',
  },
  'CORS Credentials': {
    what: 'Checks if CORS allows credentials (cookies, auth headers) from foreign origins.',
    risk: 'Combining credentials with wildcard origin allows complete session hijacking.',
    exploit: 'Attacker\'s website makes authenticated requests using the victim\'s cookies, reading private data or performing actions as the victim.',
    fix: 'Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins.',
  },

  // Performance Checks
  'Response Time': {
    what: 'Measures the total time to receive a complete response from the server.',
    risk: 'Slow response times indicate potential server misconfiguration or resource constraints.',
    exploit: 'A slow server is more susceptible to application-layer DoS attacks (Slowloris, R.U.D.Y.) because it has fewer resources to handle concurrent connections.',
    fix: 'Optimize server configuration, enable caching, use a CDN for static assets, and ensure adequate server resources.',
  },
  'Time to First Byte (TTFB)': {
    what: 'Measures the time from request sent to first byte received. Indicates server processing speed.',
    risk: 'High TTFB indicates slow server-side processing.',
    exploit: 'Attackers can exploit slow processing by sending many concurrent requests that tie up server resources.',
    fix: 'Optimize database queries, implement caching (Redis/Memcached), use PHP-FPM or equivalent for faster processing.',
  },
  'TLS Handshake Time': {
    what: 'Measures how long the SSL/TLS encryption negotiation takes.',
    risk: 'Slow TLS handshake affects all HTTPS connections and user experience.',
    exploit: 'Attackers can exploit slow TLS by initiating thousands of TLS handshakes simultaneously (TLS exhaustion attack).',
    fix: 'Enable TLS session resumption, use OCSP stapling, ensure modern cipher suites are prioritized.',
  },

  // SQL Injection Checks
  'SQL Injection Test': {
    what: 'Tests input fields and URL parameters for SQL injection vulnerabilities by sending common SQL payloads.',
    risk: 'Attackers can read, modify, or delete database contents, bypass authentication, and potentially execute system commands.',
    exploit: 'Attacker injects SQL code like \' OR 1=1 -- into login forms or URL parameters to bypass authentication, or uses UNION SELECT to extract data from other tables.',
    fix: 'Use parameterized queries (prepared statements) for all database operations. Never concatenate user input into SQL strings. Apply input validation and use an ORM.',
  },
  'Database Error Disclosure': {
    what: 'Checks if the application exposes database error messages containing table names, query structure, or database version.',
    risk: 'Database error messages reveal internal structure, making it easier for attackers to craft targeted SQL injection attacks.',
    exploit: 'Attacker sends malformed input to trigger database errors, then uses revealed table names and column information to construct precise data extraction queries.',
    fix: 'Configure custom error pages that hide technical details. Log detailed errors server-side only. Set display_errors=off in production.',
  },
  'Blind SQL Injection Test': {
    what: 'Tests for blind SQL injection where the application does not show error messages but behaves differently based on injected conditions.',
    risk: 'Even without visible errors, attackers can extract entire databases one character at a time using boolean or time-based techniques.',
    exploit: 'Attacker uses payloads like \' AND 1=1-- vs \' AND 1=2-- to observe different responses, or \' AND SLEEP(5)-- to measure response time differences, slowly extracting data.',
    fix: 'Use parameterized queries for all database operations. Implement a WAF with SQL injection rules. Monitor for unusually slow or repetitive query patterns.',
  },

  // Open Port Detection
  'Open Port Detection': {
    what: 'Scans for commonly exploited open network ports including database ports (3306, 5432), admin interfaces (8080, 8443), and other sensitive services.',
    risk: 'Unnecessary open ports expose internal services to the internet, increasing the attack surface for brute-force, exploitation, and data exfiltration.',
    exploit: 'Attacker discovers open MySQL port (3306) and uses tools like Hydra to brute-force database credentials, or finds an exposed Redis instance (6379) with no authentication.',
    fix: 'Close all unnecessary ports using firewall rules (iptables/ufw). Restrict database and admin ports to internal networks only. Use VPN for remote administration.',
  },

  // Open Redirect
  'Open Redirect Test': {
    what: 'Tests URL parameters for open redirect vulnerabilities where the application redirects users to attacker-controlled URLs.',
    risk: 'Attackers abuse trusted domain reputation to redirect users to phishing or malware sites, bypassing email filters and user suspicion.',
    exploit: 'Attacker crafts URL like trusted-site.edu/redirect?url=https://evil.com/fake-login and distributes it via phishing emails. Victims trust the university domain and click.',
    fix: 'Validate redirect URLs against a whitelist of allowed domains. Never redirect to user-supplied URLs without validation. Use relative paths for internal redirects.',
  },

  // SSRF Detection
  'SSRF Detection': {
    what: 'Tests for Server-Side Request Forgery where the application can be tricked into making requests to internal resources or arbitrary external URLs.',
    risk: 'Attackers can access internal services, cloud metadata APIs, and private network resources that are not directly accessible from the internet.',
    exploit: 'Attacker submits http://169.254.169.254/latest/meta-data/ as a URL parameter to steal cloud instance credentials, or http://localhost:6379/ to interact with internal Redis.',
    fix: 'Validate and whitelist allowed URLs and IP ranges. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). Use a dedicated HTTP client with SSRF protections.',
  },

  // Email Security Checks
  'DKIM Record': {
    what: 'Checks for DomainKeys Identified Mail (DKIM) records that cryptographically sign outgoing emails to verify they haven\'t been tampered with.',
    risk: 'Without DKIM, attackers can forge emails that appear to come from your domain, and recipients cannot verify email authenticity.',
    exploit: 'Attacker sends spoofed emails from admin@yourdomain.edu to employees requesting password resets or wire transfers. Without DKIM, email servers cannot detect the forgery.',
    fix: 'Configure DKIM by generating a key pair, publishing the public key as a DNS TXT record, and configuring your mail server to sign outgoing emails.',
  },
  'BIMI Record': {
    what: 'Checks for Brand Indicators for Message Identification (BIMI), which displays your organization\'s logo in supported email clients.',
    risk: 'Without BIMI, recipients cannot visually verify email authenticity, making phishing emails harder to distinguish from legitimate ones.',
    exploit: 'Phishing emails impersonating the organization appear identical to legitimate emails in the inbox. BIMI-enabled legitimate emails display the official logo, helping users identify real messages.',
    fix: 'Set up BIMI by publishing a BIMI DNS record pointing to your SVG logo. Requires DMARC enforcement (p=quarantine or p=reject) as a prerequisite.',
  },
  'Email Security Score': {
    what: 'Evaluates the overall email security posture by checking SPF, DKIM, DMARC, and BIMI configuration completeness and strength.',
    risk: 'Incomplete email security allows various spoofing and phishing attacks that damage organization reputation and compromise user accounts.',
    exploit: 'Attacker exploits gaps in email authentication chain — e.g., SPF exists but DMARC is set to p=none, meaning spoofed emails are still delivered to recipients.',
    fix: 'Implement all four email security layers: SPF (restrict senders), DKIM (sign emails), DMARC (enforce policy with p=reject), and BIMI (brand verification).',
  },

  // WAF Detection
  'WAF Detection': {
    what: 'Detects whether a Web Application Firewall (WAF) is protecting the website by analyzing response headers, cookies, and behavior patterns.',
    risk: 'Without a WAF, all malicious traffic reaches the application directly, relying solely on application-level security which may have gaps.',
    exploit: 'Attacker uses automated scanning tools (sqlmap, nikto, nuclei) to send thousands of attack payloads directly to the application. Without a WAF, these all reach the server.',
    fix: 'Deploy a WAF such as Cloudflare WAF, AWS WAF, or ModSecurity. Configure rules to block OWASP Top 10 attack patterns and enable rate limiting.',
  },

  // DNS Zone Transfer
  'DNS Zone Transfer': {
    what: 'Tests if the DNS server allows unrestricted zone transfers (AXFR), which would expose all DNS records including internal subdomains.',
    risk: 'Unrestricted zone transfers reveal the complete DNS infrastructure, including internal hostnames, mail servers, and hidden services.',
    exploit: 'Attacker runs dig axfr yourdomain.edu to dump all DNS records, discovering internal subdomains like admin.yourdomain.edu, staging.yourdomain.edu, and vpn.yourdomain.edu.',
    fix: 'Restrict zone transfers to authorized secondary nameservers only. Configure allow-transfer in BIND or equivalent setting in your DNS server to list specific IPs.',
  },
}

export function getCheckExplanation(checkName) {
  return checkExplanations[checkName] || null
}

export function getCategoryInfo(category) {
  return categoryInfo[category] || null
}
