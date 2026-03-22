# VScan-MOHESR

**Website Security Scanner** — منصة فحص أمان المواقع الإلكترونية

A comprehensive web security assessment platform with a 1000-point scoring system, designed for evaluating educational institution websites.

## Features

### 16 Security Categories | 60+ Checks | 1000-Point Scale

| # | Category | Weight | Checks | Description |
|---|----------|--------|--------|-------------|
| 1 | SSL/TLS | 20% | 4 | HTTPS, certificate, TLS version, redirect |
| 2 | Security Headers | 20% | 7 | HSTS, CSP, X-Frame-Options, etc. |
| 3 | Cookie Security | 10% | dynamic | Secure, HttpOnly, SameSite flags |
| 4 | Server Info | 15% | 3 | Server header, X-Powered-By, CMS detection |
| 5 | Directory & Files | 10% | 9 | Sensitive file exposure (.env, .git, admin) |
| 6 | Performance | 15% | 3 | Response time, TTFB, TLS handshake |
| 7 | DDoS Protection | 10% | 3 | CDN, WAF, rate limiting |
| 8 | CORS | 10% | 2 | Wildcard origin, credentials |
| 9 | HTTP Methods | 8% | 2 | Dangerous methods (TRACE, DELETE, PUT) |
| 10 | DNS Security | 8% | 3 | SPF, DMARC, CAA |
| 11 | Mixed Content | 7% | 3 | HTTP resources on HTTPS pages |
| 12 | Info Disclosure | 7% | 3 | Error pages, comments, versions |
| 13 | Hosting Quality | 12% | 6 | HTTP/2, HTTP/3, Brotli, IPv6, DNS speed |
| 14 | Content Optimization | 8% | 3 | Cache headers, page size, compression |
| 15 | Advanced Security | 5% | 4 | COEP, COOP, CORP, OCSP Stapling |
| 16 | Malware & Threats | 10% | 6 | Malicious JS, hidden iframes, crypto miners |

### Additional Features

- **AI Analysis** — DeepSeek/OpenAI integration for automated fix recommendations
- **Leaderboard** — Rank all websites by overall or per-category score
- **Category Filtering** — Sort rankings by any of the 16 categories
- **Institution Filtering** — Filter by institution type (government/private)
- **Real-time Progress** — Live progress bar during scanning
- **Bulk Import** — Add hundreds of targets via CSV
- **User Management** — Admin/user roles with JWT authentication
- **Public Methodology** — Transparent scoring criteria (Arabic + English)
- **SEO Optimized** — Landing page with meta tags and structured data

### Grading Scale

| Grade | Score | Label |
|-------|-------|-------|
| A+ | 900-1000 | Excellent |
| A | 800-899 | Very Good |
| B | 700-799 | Good |
| C | 600-699 | Average |
| D | 500-599 | Below Average |
| F | 0-499 | Failing |

## Tech Stack

- **Backend:** Go (Fiber + GORM + SQLite/PostgreSQL)
- **Frontend:** Vue.js 3 + Tailwind CSS + Chart.js
- **Deployment:** Docker + Coolify
- **AI:** DeepSeek / OpenAI compatible APIs

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

**Default login:** `admin` / `admin123`

### Docker Deployment

```bash
docker compose up -d
```

### Coolify Deployment

1. Create new resource → **Dockerfile** build pack
2. Point to this repository
3. Set port to **80**
4. Add volume: `/app/data` for database persistence

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DRIVER` | `sqlite` | Database driver (`sqlite` or `postgres`) |
| `DB_PATH` | `vscan.db` | SQLite database path |
| `DATABASE_URL` | - | PostgreSQL connection string |
| `JWT_SECRET` | (built-in) | JWT signing secret |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

## API Endpoints

### Public
- `GET /health` — Health check
- `GET /api/criteria` — Scoring methodology (JSON)
- `POST /api/auth/login` — Authentication

### Protected (requires JWT)
- `GET /api/dashboard` — Dashboard statistics
- `GET /api/leaderboard` — Rankings with category filtering
- `GET/POST /api/targets` — Manage scan targets
- `POST /api/scans/start` — Start batch scan
- `GET /api/scans/:id` — Scan progress & results
- `GET /api/results/:id` — Detailed scan report
- `POST /api/ai/analyze/:id` — AI analysis

### Admin Only
- `GET/POST /api/users` — User management
- `GET/PUT /api/settings` — System settings

## Seeded Data

Pre-loaded with **111 Iraqi universities** (35 government + 76 private) from the Ministry of Higher Education and Scientific Research (MOHESR).

## License

Private — All rights reserved.

---

Built with Claude Code by [haydary1986](https://github.com/haydary1986)
