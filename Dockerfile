# Stage 1: Build Vue.js frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.25-alpine AS backend-builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ .
RUN CGO_ENABLED=1 GOOS=linux go build -o vscan-server ./cmd/main.go
# Cross-compile the local scan agent (CGO-free) for the download page
RUN mkdir -p /agents \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o /agents/seku-agent-windows-amd64.exe ./cmd/agent \
 && CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o /agents/seku-agent-macos-arm64 ./cmd/agent \
 && CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o /agents/seku-agent-macos-intel ./cmd/agent \
 && CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o /agents/seku-agent-linux-amd64 ./cmd/agent

# Stage 2b: Fetch nuclei binary + templates (isolated — not part of Seku's go.mod).
# Powers the optional "nuclei" scanner (enable at runtime with SEKU_ENABLE_NUCLEI=1).
# Latest Go — the PD tools (nuclei v3.11+ needs Go >= 1.26) build here,
# independent of the app's backend-builder which stays on go 1.25.
FROM golang:alpine AS nuclei-builder
RUN apk add --no-cache git ca-certificates curl
ENV CGO_ENABLED=0 HOME=/root
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/hahwul/dalfox/v2@latest
RUN go install github.com/ffuf/ffuf/v2@latest
# Passive URL discovery (historical endpoints from Wayback/CommonCrawl/OTX/URLScan)
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/tomnomnom/waybackurls@latest
# Clone nuclei-templates directly — `nuclei -update-templates` printed the banner
# and exited without downloading, leaving an empty templates dir (0 matches).
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
    && rm -rf /root/nuclei-templates/.git

# Comprehensive wordlists (SecLists + OneListForAll) baked into the image.
# The scanners default to these via ENV (see final stage) and fall back to the
# small embedded lists if a download failed.
ARG SL=https://raw.githubusercontent.com/danielmiessler/SecLists/master
ARG OLFA=https://raw.githubusercontent.com/six2dez/OneListForAll/main
RUN mkdir -p /wordlists && \
    (curl -fsSL -o /wordlists/content.txt       "$SL/Discovery/Web-Content/common.txt" || true) && \
    (curl -fsSL -o /wordlists/content-large.txt "$OLFA/onelistforallmicro.txt" || true) && \
    (curl -fsSL -o /wordlists/passwords.txt     "$SL/Passwords/Common-Credentials/10k-most-common.txt" || true) && \
    (curl -fsSL -o /wordlists/users.txt         "$SL/Usernames/top-usernames-shortlist.txt" || true) && \
    (curl -fsSL "$SL/Usernames/cirt-default-usernames.txt" >> /wordlists/users.txt 2>/dev/null || true)

# Stage 3: Final runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates sqlite-libs nginx
ENV HOME=/root

WORKDIR /app

# Copy Go binary
COPY --from=backend-builder /app/backend/vscan-server .

# Baked agent binaries served by the download page
COPY --from=backend-builder /agents /app/agents

# nuclei binary + templates (optional engine; the scanner degrades gracefully if absent)
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-builder /go/bin/katana /usr/local/bin/katana
COPY --from=nuclei-builder /go/bin/dalfox /usr/local/bin/dalfox
COPY --from=nuclei-builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=nuclei-builder /go/bin/gau /usr/local/bin/gau
COPY --from=nuclei-builder /go/bin/waybackurls /usr/local/bin/waybackurls
COPY --from=nuclei-builder /root/nuclei-templates /root/nuclei-templates
COPY --from=nuclei-builder /wordlists /app/wordlists
# Scanners default to the comprehensive baked wordlists (fall back to embedded if absent)
ENV SEKU_FFUF_WORDLIST=/app/wordlists/content.txt \
    SEKU_LOGIN_PASS_FILE=/app/wordlists/passwords.txt \
    SEKU_LOGIN_USERS_FILE=/app/wordlists/users.txt \
    SEKU_NUCLEI_TEMPLATES_DIR=/root/nuclei-templates

# Copy fonts for PDF Arabic support
COPY backend/assets/fonts/ /app/assets/fonts/

# Copy Vue.js build output
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# Persistent data directory for SQLite database
RUN mkdir -p /app/data /run/nginx

# Nginx config
COPY <<'NGINX' /etc/nginx/http.d/default.conf
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
NGINX

# Start script - database stored in /app/data volume for persistence.
# PORT is pinned to 8080 because nginx owns :80 in this combined image and
# proxies /api/ and /ws/ to 127.0.0.1:8080. This overrides any PORT injected by
# the orchestrator (e.g. Coolify sets PORT=80 from the exposed port), which would
# otherwise make the backend bind :80 and crash with "address already in use".
COPY <<'SCRIPT' /app/start.sh
#!/bin/sh
DB_PATH=/app/data/vscan.db PORT=8080 ./vscan-server &
nginx -g "daemon off;"
SCRIPT
RUN chmod +x /app/start.sh

# Volume for persistent data (survives redeployments)
VOLUME ["/app/data"]

EXPOSE 80

CMD ["/app/start.sh"]
