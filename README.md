# VScan-MOHESR

**Website Security Scanner** — منصة فحص أمان المواقع الإلكترونية

A comprehensive web security assessment platform with a 1000-point scoring system, designed for evaluating educational and governmental institution websites.

## Features

### 17 Security Categories | 66 Checks | 1000-Point Scale

| # | Category | Weight | Checks | Description |
|---|----------|--------|--------|-------------|
| 1 | SSL/TLS | 20% | 4 | HTTPS availability, certificate validity, TLS version, HTTPS redirect |
| 2 | Security Headers | 20% | 7 | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, XSS-Protection, Referrer-Policy, Permissions-Policy |
| 3 | Cookie Security | 10% | dynamic | Secure, HttpOnly, SameSite flags per cookie |
| 4 | Server Info | 15% | 3 | Server header exposure, X-Powered-By, CMS detection |
| 5 | Directory & Files | 10% | 9 | Sensitive file exposure (.env, .git, admin, backup, config) |
| 6 | Performance | 15% | 3 | Response time, TTFB (linear decay scoring), TLS handshake speed |
| 7 | DDoS Protection | 10% | 3 | CDN detection (Cloudflare/AWS/Akamai), WAF, rate limiting |
| 8 | CORS | 10% | 2 | Wildcard origin, credentials misconfiguration |
| 9 | HTTP Methods | 8% | 2 | Dangerous methods (TRACE, DELETE, PUT, PATCH), OPTIONS disclosure |
| 10 | DNS Security | 8% | 3 | SPF record, DMARC policy, CAA records |
| 11 | Mixed Content | 7% | 3 | HTTP scripts/CSS on HTTPS, mixed images, insecure forms |
| 12 | Info Disclosure | 7% | 3 | Error page leaks, HTML comments, technology version exposure |
| 13 | Hosting Quality | 12% | 6 | HTTP/2, HTTP/3 QUIC, Brotli compression, IPv6, Keep-Alive, DNS resolution time |
| 14 | Content Optimization | 8% | 3 | Cache-Control headers, page size analysis, compression ratio |
| 15 | Advanced Security | 5% | 4 | COEP, COOP, CORP, OCSP Stapling |
| 16 | Malware & Threats | 10% | 6 | Malicious JavaScript, hidden iframes, crypto miners, suspicious redirects, malware signatures, malicious external links |
| 17 | Threat Intelligence | 8% | 4 | Cryptojacking detection, C2 server communication, DNS blacklist check (8 DNSBLs), domain age & reputation (RDAP/WHOIS) |

### Platform Features

- **AI-Powered Analysis** — DeepSeek/OpenAI integration for automated vulnerability analysis and fix recommendations with step-by-step remediation guides
- **Leaderboard** — Rank all websites by overall score or any specific category
- **Category Filtering** — Sort rankings by any of the 17 security categories
- **Institution Filtering** — Filter by institution type (government / private)
- **Real-time Progress** — Live progress bar with completion percentage during scanning
- **Bulk Import** — Add hundreds of targets via CSV (URL, name, institution)
- **User Management** — Admin/user roles with JWT authentication
- **Public Methodology** — Transparent scoring criteria available in Arabic and English
- **SEO Optimized** — Landing page with Open Graph, Twitter Cards, and Schema.org structured data
- **Arabic RTL Support** — Full right-to-left layout with Arabic landing page and methodology

### Grading Scale

| Grade | Score Range | Label |
|-------|------------|-------|
| A+ | 900 — 1000 | Excellent |
| A | 800 — 899 | Very Good |
| B | 700 — 799 | Good |
| C | 600 — 699 | Average |
| D | 500 — 599 | Below Average |
| F | 0 — 499 | Failing |

## Architecture

```
vscan-mohesr/
├── backend/                          # Go API Server
│   ├── cmd/main.go                   # Entry point
│   ├── internal/
│   │   ├── api/                      # REST API handlers, auth, middleware
│   │   ├── config/                   # Database initialization, seed data
│   │   ├── models/                   # GORM data models
│   │   └── scanner/                  # 17 security scanner implementations
│   └── Dockerfile
├── frontend/                         # Vue.js SPA
│   ├── src/
│   │   ├── views/                    # 12 pages (Landing, Dashboard, Scans, etc.)
│   │   ├── data/                     # Security knowledge base
│   │   ├── router/                   # Vue Router with auth guards
│   │   └── api.js                    # Axios HTTP client
│   └── Dockerfile
├── docker-compose.yml                # Multi-service deployment
├── Dockerfile                        # Single-container deployment (Coolify)
└── guides/                           # Security hardening guides
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.25, Fiber v2, GORM |
| Frontend | Vue.js 3, Tailwind CSS 4, Chart.js, Vite |
| Database | SQLite (dev) / PostgreSQL (production) |
| Deployment | Docker, Coolify |
| AI | DeepSeek / OpenAI compatible APIs |

## Quick Start

### Local Development

```bash
# Backend
cd backend
go run ./cmd/main.go

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`

**Default credentials:** `admin` / `admin123`

### Docker Deployment

```bash
docker compose up -d
```

### Coolify Deployment

1. Create new resource → **Dockerfile** build pack
2. Point to this repository
3. Set port to **80**
4. Add persistent storage volume: `/app/data`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DRIVER` | `sqlite` | Database driver (`sqlite` or `postgres`) |
| `DB_PATH` | `vscan.db` | SQLite database file path |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `JWT_SECRET` | (built-in) | JWT signing secret (change in production) |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

## API Reference

### Public Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/criteria` | Full scoring methodology (JSON) |
| `POST` | `/api/auth/login` | User authentication |

### Protected Endpoints (JWT required)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/dashboard` | Dashboard statistics with score distribution |
| `GET` | `/api/leaderboard` | Rankings with category & institution filtering |
| `GET` | `/api/targets` | List scan targets |
| `POST` | `/api/targets` | Add single target |
| `POST` | `/api/targets/bulk` | Bulk import targets |
| `POST` | `/api/scans/start` | Start batch security scan |
| `GET` | `/api/scans/:id` | Scan job details with real-time progress |
| `GET` | `/api/results/:id` | Detailed scan result with categorized checks |
| `POST` | `/api/ai/analyze/:id` | Generate AI security analysis |
| `GET` | `/api/ai/analysis/:id` | Retrieve AI analysis report |

### Admin Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/users` | User management |
| `PUT/DELETE` | `/api/users/:id` | Update/delete user |
| `GET/PUT` | `/api/settings` | System settings (AI provider config) |

## Seeded Data

Pre-loaded with **111 Iraqi universities** (35 government + 76 private) from the Ministry of Higher Education and Scientific Research (MOHESR), including:
- University of Baghdad, Al-Mustansiriyah University, University of Technology
- University of Mosul, University of Basrah, University of Kufa
- Al-Turath University, Al-Rafidain University, Al-Mamoun University
- And 100+ more institutions

## Scoring Methodology

The scoring system uses a **weighted average** approach:

1. Each website is scanned across **17 categories**
2. Each category contains **multiple checks** with individual weights
3. Every check produces a score from **0 to 1000**
4. Category score = weighted average of its checks
5. Overall score = weighted average of all category scores

The full methodology is publicly available at `/methodology` (English) and `/methodology-ar` (Arabic).

## License

All rights reserved.
