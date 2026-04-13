<div align="center">

# 🛡️ Seku

**Powered by Irtikaz Technical Solutions — شركة ارتكاز للحلول التقنية**

**The Open-Source Web Security Scanner with 1000-Point Scoring**

Scan websites across **25 security categories** with granular 0–1000 scoring,
OWASP Top 10 + CVSS v3.1 mapping, and automated remediation guides.

[![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![Vue.js](https://img.shields.io/badge/Vue.js-3-4FC08D?style=flat-square&logo=vuedotjs)](https://vuejs.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/haydary1986/seku?style=flat-square)](https://github.com/haydary1986/seku/stargazers)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](https://github.com/haydary1986/seku/pkgs/container/seku)

[Quick Start](#-quick-start) · [Features](#-features) · [Documentation](#-documentation) · [Contributing](#-contributing)

</div>

---

## ⚡ Quick Start

```bash
# One-liner: scan any website
docker run --rm ghcr.io/haydary1986/seku example.com

# Or install the CLI
curl -sSL https://raw.githubusercontent.com/haydary1986/seku/main/install.sh | bash
vscan example.com

# Or use as GitHub Action
- uses: haydary1986/seku@v1
  with:
    url: https://example.com
```

**Output:**
```
╔═══════════════════════════════════════════════════╗
║  Seku Security Report — example.com              ║
║  Score: 847/1000 (Grade: A)                      ║
╠═══════════════════════════════════════════════════╣
║ ✅ SSL/TLS          ████████████████████░  950    ║
║ ✅ Security Headers  ████████████████░░░░  820    ║
║ ⚠️  HTTP Methods      ██████████████░░░░░░  700    ║
║ ❌ Mixed Content     ████████░░░░░░░░░░░░  400    ║
║ ...                                               ║
╚═══════════════════════════════════════════════════╝
```

## ✨ Features

### 🔍 22 Security Scan Categories

<table>
<tr>
<td width="50%">

**Core Security**
- 🔒 SSL/TLS (HTTPS, certs, TLS version)
- 🛡️ Security Headers (HSTS, CSP, X-Frame)
- 🍪 Cookie Security (Secure, HttpOnly, SameSite)
- 🌐 CORS Configuration
- 🔑 HTTP Methods (TRACE, DELETE blocking)
- 📧 DNS Security (SPF, DMARC, CAA)

</td>
<td>

**Advanced Analysis**
- 🦠 Malware & Threats Detection
- ⚡ XSS Vulnerability Scanner
- 📦 JS Library Vulnerabilities
- 🔌 Third-Party Script Risk
- 📄 WordPress Deep Scanner
- 🏗️ SEO & Technical Health

</td>
</tr>
<tr>
<td>

**Infrastructure**
- 🚀 Hosting Quality (HTTP/2, HTTP/3, Brotli)
- 📊 Performance (TTFB, response time)
- 🛡️ DDoS Protection (CDN, WAF)
- 🔍 Content Optimization (cache, compression)
- 🔐 Advanced Security (COEP, COOP, CORP)

</td>
<td>

**Intelligence**
- 🕵️ Information Disclosure
- 📂 Directory & File Exposure
- 🖥️ Server Info Leakage
- 🔗 Mixed Content Detection
- 🧠 Threat Intelligence (C2, blacklists)

</td>
</tr>
</table>

### 🔬 Smart Analysis & Remediation

- **Multi-LLM Integration**: Pluggable architecture supporting DeepSeek, OpenAI, Claude, Gemini, and Ollama
- **Interactive Chat**: Ask questions about scan results and get contextual answers
- **Auto-Remediation Engine**: Step-by-step fix guides for 7 server types (Apache, Nginx, IIS, LiteSpeed, Caddy, Tomcat, Node.js)
- **CVE-Aware Upgrades**: Library vulnerability detection with upgrade recommendations

### 📊 Enterprise Features

| Feature | Free | Basic | Pro | Enterprise |
|---------|:----:|:-----:|:---:|:----------:|
| Scan Categories | 5 | 12 | 17 | 22 |
| Targets | 5 | 25 | 100 | ∞ |
| Scans/month | 10 | 50 | 200 | ∞ |
| PDF Reports | ❌ | ✅ | ✅ | ✅ |
| SARIF Export | ❌ | ❌ | ✅ | ✅ |
| LLM Analysis | ❌ | 10/mo | 50/mo | ∞ |
| Scheduled Scans | ❌ | Weekly | Daily | Custom |
| API Access | ❌ | Read | Full | Full |
| Webhooks | ❌ | ❌ | ✅ | ✅ |

### 🏆 Grading Scale

| Grade | Score | Description |
|:-----:|:-----:|:------------|
| **A+** | 900–1000 | Excellent security posture |
| **A** | 800–899 | Strong security |
| **B** | 700–799 | Good with minor issues |
| **C** | 600–699 | Average — needs improvement |
| **D** | 500–599 | Below average — significant gaps |
| **F** | 0–499 | Failing — critical issues |

## 🚀 Installation

### CLI (Recommended)

```bash
# macOS / Linux
curl -sSL https://raw.githubusercontent.com/haydary1986/seku/main/install.sh | bash

# Docker
docker pull ghcr.io/haydary1986/seku

# From source
git clone https://github.com/haydary1986/seku.git
cd seku/backend
go build -o vscan ./cmd/cli/main.go
```

### Web Dashboard

```bash
git clone https://github.com/haydary1986/seku.git
cd seku
docker compose up -d
# Open http://localhost (admin / admin123)
```

## 📖 CLI Usage

```bash
# Scan a single URL
vscan example.com
vscan -url https://example.com

# Scan multiple URLs
vscan -urls "site1.com,site2.com,site3.com"

# Scan from file
vscan -file urls.txt

# JSON output
vscan example.com -output json -o results.json

# SARIF for GitHub Security tab
vscan example.com -output sarif -o results.sarif

# Filter by severity
vscan example.com -severity high

# Choose scan depth
vscan example.com -plan free        # 5 categories
vscan example.com -plan basic       # 12 categories
vscan example.com -plan pro         # 17 categories
vscan example.com -plan enterprise  # 22 categories (default)
```

## 🔧 GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: haydary1986/seku@v1
        with:
          url: https://your-site.com
          output: sarif
          output-file: results.sarif
          fail-on-score: 700

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## 🏗️ Architecture

```
seku/
├── backend/                    # Go API + CLI
│   ├── cmd/
│   │   ├── main.go            # Web server entry point
│   │   └── cli/main.go        # CLI tool
│   └── internal/
│       ├── scanner/           # 22 security scanners
│       ├── api/               # REST API handlers & middleware
│       ├── models/            # GORM data models
│       ├── services/          # PDF, SARIF, webhooks
│       ├── scheduler/         # Scheduled scan jobs
│       ├── reports/           # Report generation
│       └── ws/                # WebSocket real-time hub
├── frontend/                   # Vue.js 3 SPA (22 views)
│   ├── src/views/             # Dashboard, Scans, AI Chat, etc.
│   └── Dockerfile
├── action.yml                  # GitHub Action definition
├── Dockerfile                  # Web dashboard container
├── Dockerfile.cli              # CLI container
├── docker-compose.yml          # Multi-service deployment
├── install.sh                  # CLI installer
└── guides/                     # Security hardening guides
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.25, Fiber v2, GORM |
| Frontend | Vue.js 3, Tailwind CSS 4, Chart.js, Vite |
| Database | SQLite (dev) / PostgreSQL (production) |
| Real-time | WebSocket with progress streaming |
| Deployment | Docker, Docker Compose, Coolify |
| LLM Integration | DeepSeek, OpenAI, Claude, Gemini, Ollama |

## 🔌 API

```bash
# Authenticate
TOKEN=$(curl -s -X POST https://your-instance.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token')

# Start a scan
curl -X POST https://your-instance.com/api/scans/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Scan","target_ids":[1,2,3]}'

# Get results
curl https://your-instance.com/api/results/1 \
  -H "Authorization: Bearer $TOKEN"

# Or use API Key (Pro / Enterprise)
curl https://your-instance.com/api/targets \
  -H "X-API-Key: vsk_your_key_here"
```

<details>
<summary><strong>Full API Reference</strong></summary>

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/criteria` | Full scoring methodology (JSON) |
| `POST` | `/api/auth/login` | User authentication |
| `POST` | `/api/auth/register` | User registration |

### Protected Endpoints (JWT Required)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/dashboard` | Dashboard statistics with score distribution |
| `GET` | `/api/leaderboard` | Rankings with category & institution filtering |
| `GET` | `/api/targets` | List scan targets |
| `POST` | `/api/targets` | Add single target |
| `POST` | `/api/targets/bulk` | Bulk import targets via CSV |
| `POST` | `/api/scans/start` | Start batch security scan |
| `GET` | `/api/scans/:id` | Scan job details with real-time progress |
| `GET` | `/api/results/:id` | Detailed scan result with categorized checks |
| `POST` | `/api/ai/analyze/:id` | Generate security analysis |
| `GET` | `/api/ai/analysis/:id` | Retrieve analysis report |

### Admin Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/users` | User management |
| `PUT/DELETE` | `/api/users/:id` | Update / delete user |
| `GET/PUT` | `/api/settings` | System settings (LLM provider config) |

</details>

## 📊 OWASP Top 10 Mapping

Every finding maps to OWASP Top 10 (2021) and CWE identifiers:

| OWASP | Category | Seku Coverage |
|-------|----------|---------------|
| A01 | Broken Access Control | CORS, HTTP Methods, Directory Exposure |
| A02 | Cryptographic Failures | SSL/TLS, Mixed Content |
| A03 | Injection | XSS Scanner, Malware Detection |
| A04 | Insecure Design | DDoS Protection, Rate Limiting |
| A05 | Security Misconfiguration | Security Headers, Server Info |
| A06 | Vulnerable Components | JS Libraries, WordPress Scanner |
| A07 | Auth Failures | DNS (SPF/DMARC), Cookie Security |
| A08 | Data Integrity Failures | Third-Party SRI, Content Optimization |

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DRIVER` | `sqlite` | Database driver (`sqlite` or `postgres`) |
| `DB_PATH` | `vscan.db` | SQLite database file path |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `JWT_SECRET` | (built-in) | JWT signing secret (change in production!) |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

### Coolify Deployment

1. Create new resource with **Dockerfile** build pack
2. Point to this repository
3. Set port to **80**
4. Add persistent storage volume: `/app/data`

## 📖 Documentation

| Document | Language | Description |
|----------|----------|-------------|
| **[Scanner Reference](docs/SCANNERS.md)** | English | Complete technical reference for all 25 scanners, 80+ checks, scoring thresholds, OWASP/CWE/CVSS mappings |
| **[مرجع الفاحصات](docs/SCANNERS-AR.md)** | العربية | المرجع التقني الكامل لجميع الفاحصات الـ 25 مع شرح تفصيلي لكل فحص |
| **[Methodology](/methodology)** | English | Public scoring methodology page |
| **[منهجية التقييم](/methodology-ar)** | العربية | صفحة معايير التقييم العامة |
| **[Contributing](CONTRIBUTING.md)** | English | How to contribute to the project |
| **[API Docs](/api/docs)** | English | REST API documentation (JSON) |

## 🌍 Internationalization

- 🇬🇧 English — full support
- 🇮🇶 Arabic — full RTL support with dedicated methodology page
- Scanner documentation available in both languages

## 📋 Scoring Methodology

The scoring system uses a **weighted average** approach:

1. Each website is scanned across **25 categories** (80+ individual checks)
2. Each category contains **multiple checks** with individual weights
3. Every check produces a score from **0 to 1000**
4. Category score = weighted average of its checks
5. Overall score = weighted average of all category scores
6. Each finding mapped to **OWASP Top 10**, **CWE**, and **CVSS v3.1**

The full methodology is publicly available and transparent — no black boxes.
See **[docs/SCANNERS.md](docs/SCANNERS.md)** for complete scoring details.

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/haydary1986/seku.git
cd seku

# Backend
cd backend && go run ./cmd/main.go

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

Open `http://localhost:5173` — default credentials: `admin` / `admin123`

## 📝 License

[MIT License](LICENSE) — use it freely in your projects.

## ⭐ Star History

If Seku helps secure your websites, please star the repo — it helps others discover it!

[![Star History Chart](https://api.star-history.com/svg?repos=haydary1986/seku&type=Date)](https://star-history.com/#haydary1986/seku&Date)

---

<div align="center">
<strong>Designed & engineered by <a href="https://github.com/haydary1986">@haydary1986</a></strong>
<br><br>
<a href="https://github.com/haydary1986/seku/issues">Report Bug</a> · <a href="https://github.com/haydary1986/seku/issues">Request Feature</a> · <a href="https://github.com/haydary1986/seku/discussions">Discussions</a>
</div>
