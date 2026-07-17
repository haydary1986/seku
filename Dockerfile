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

# Stage 3: Final runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates sqlite-libs nginx

WORKDIR /app

# Copy Go binary
COPY --from=backend-builder /app/backend/vscan-server .

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
