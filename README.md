# Cloudflare Prometheus Exporter

Exports Cloudflare zone analytics as Prometheus metrics. Auto-discovers all
active zones on the account — no zone IDs needed.

## Metrics exposed

| Metric | Description |
|--------|-------------|
| `cloudflare_requests_total` | Total requests |
| `cloudflare_requests_cached_total` | Cached requests |
| `cloudflare_requests_uncached_total` | Uncached requests |
| `cloudflare_requests_cache_hit_ratio` | Cache hit ratio (0–1) |
| `cloudflare_requests_by_status_total` | Requests by HTTP status code |
| `cloudflare_requests_by_country_total` | Requests by country |
| `cloudflare_bandwidth_bytes_total` | Total bandwidth in bytes |
| `cloudflare_bandwidth_cached_bytes_total` | Cached bandwidth |
| `cloudflare_bandwidth_uncached_bytes_total` | Uncached bandwidth |
| `cloudflare_threats_total` | Threats blocked |
| `cloudflare_threats_by_country_total` | Threats by country |
| `cloudflare_threats_by_type_total` | Threats by type |
| `cloudflare_pageviews_total` | Pageviews |
| `cloudflare_unique_visitors_total` | Unique visitors |
| `cloudflare_ssl_requests_encrypted_total` | HTTPS requests |
| `cloudflare_ssl_requests_unencrypted_total` | HTTP requests |
| `cloudflare_scrape_success` | 1 if last scrape succeeded |
| `cloudflare_last_scrape_timestamp` | Unix timestamp of last scrape |

All metrics have `zone_id` and `zone_name` labels.

## Setup

### 1. Create a Cloudflare API token

Go to https://dash.cloudflare.com/profile/api-tokens → Create Token

Permissions needed:
- `Zone → Analytics → Read`
- `Zone → Zone → Read`

Set Zone Resources to: `All zones` (or specific zones if preferred)

### 2. Add to your .env file

```
CF_API_TOKEN=your_token_here
```

### 3. Add to docker-compose.yml

```yaml
  cloudflare-exporter:
    build: ./cloudflare-exporter
    container_name: cloudflare-exporter
    ports:
      - "9199:9199"
    environment:
      - CF_API_TOKEN=${CF_API_TOKEN}
    restart: unless-stopped
```

### 4. Add to prometheus.yml

```yaml
  - job_name: cloudflare
    scrape_interval: 60s
    static_configs:
      - targets: ['cloudflare-exporter:9199']
```

### 5. Build and start

```bash
docker compose up -d --build cloudflare-exporter
```

### 6. Verify

```bash
curl http://localhost:9199/metrics | grep cloudflare_requests
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CF_API_TOKEN` | required | Cloudflare API token |
| `PORT` | `9199` | Port to listen on |
| `SCRAPE_INTERVAL_SECONDS` | `60` | How often to poll Cloudflare API |
| `CF_SINCE_MINUTES` | `1440` | Analytics window in minutes (max 4320 = 3 days on free tier) |

## Notes

- Uses the **Cloudflare GraphQL Analytics API** (`httpRequests1hGroups`) — the old REST `/analytics/dashboard` endpoint is deprecated and returns 500
- Cloudflare free tier retains hourly analytics for **3 days** (4320 minutes max)
- The exporter sums all hourly buckets in the window into a single total per metric
- Scrape interval of 60s is recommended — polling faster won't give you more data
- API token needs `Zone:Analytics:Read` + `Zone:Zone:Read` permissions