FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cloudflare-exporter .

# ── Final image ───────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /app/cloudflare-exporter /cloudflare-exporter
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9199

ENTRYPOINT ["/cloudflare-exporter"]