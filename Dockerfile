# Stage 1: Build Vue.js frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.23-alpine AS backend-builder
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

# Copy Vue.js build output
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# Nginx config
RUN mkdir -p /run/nginx
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

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
NGINX

# Start script - run both backend and nginx
COPY <<'SCRIPT' /app/start.sh
#!/bin/sh
./vscan-server &
nginx -g "daemon off;"
SCRIPT
RUN chmod +x /app/start.sh

EXPOSE 80

CMD ["/app/start.sh"]
