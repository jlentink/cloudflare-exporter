package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ── Cloudflare API types ────────────────────────────────────────────────────

type ZoneListResponse struct {
	Result  []Zone `json:"result"`
	Success bool   `json:"success"`
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GraphQL response types

type GraphQLResponse struct {
	Data   GraphQLData `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type GraphQLData struct {
	Viewer GraphQLViewer `json:"viewer"`
}

type GraphQLViewer struct {
	Zones []GraphQLZone `json:"zones"`
}

type GraphQLZone struct {
	Groups []HourGroup `json:"httpRequests1hGroups"`
}

type HourGroup struct {
	Sum  HourSum  `json:"sum"`
	Uniq HourUniq `json:"uniq"`
}

type HourSum struct {
	Requests          int64          `json:"requests"`
	Bytes             int64          `json:"bytes"`
	CachedRequests    int64          `json:"cachedRequests"`
	CachedBytes       int64          `json:"cachedBytes"`
	PageViews         int64          `json:"pageViews"`
	Threats           int64          `json:"threats"`
	EncryptedBytes    int64          `json:"encryptedBytes"`
	EncryptedRequests int64          `json:"encryptedRequests"`
	CountryMap        []CountryEntry `json:"countryMap"`
	ResponseStatusMap []StatusEntry  `json:"responseStatusMap"`
	ThreatPathingMap  []ThreatEntry  `json:"threatPathingMap"`
}

type HourUniq struct {
	Uniques int64 `json:"uniques"`
}

type CountryEntry struct {
	ClientCountryName string `json:"clientCountryName"`
	Requests          int64  `json:"requests"`
	Bytes             int64  `json:"bytes"`
	Threats           int64  `json:"threats"`
}

type StatusEntry struct {
	EdgeResponseStatus int   `json:"edgeResponseStatus"`
	Requests           int64 `json:"requests"`
}

type ThreatEntry struct {
	ThreatPathingName string `json:"threatPathingName"`
	Requests          int64  `json:"requests"`
}

// ── Prometheus metrics ──────────────────────────────────────────────────────

var (
	cfRequestsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_requests_total",
		Help: "Total number of requests",
	}, []string{"zone_id", "zone_name"})

	cfRequestsCached = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_requests_cached_total",
		Help: "Total number of cached requests",
	}, []string{"zone_id", "zone_name"})

	cfRequestsUncached = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_requests_uncached_total",
		Help: "Total number of uncached requests",
	}, []string{"zone_id", "zone_name"})

	cfRequestsCacheHitRatio = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_requests_cache_hit_ratio",
		Help: "Cache hit ratio (0-1)",
	}, []string{"zone_id", "zone_name"})

	cfRequestsByStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_requests_by_status_total",
		Help: "Total requests by HTTP status code",
	}, []string{"zone_id", "zone_name", "status"})

	cfRequestsByCountry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_requests_by_country_total",
		Help: "Total requests by country",
	}, []string{"zone_id", "zone_name", "country"})

	cfBandwidthTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_bandwidth_bytes_total",
		Help: "Total bandwidth in bytes",
	}, []string{"zone_id", "zone_name"})

	cfBandwidthCached = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_bandwidth_cached_bytes_total",
		Help: "Cached bandwidth in bytes",
	}, []string{"zone_id", "zone_name"})

	cfBandwidthUncached = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_bandwidth_uncached_bytes_total",
		Help: "Uncached bandwidth in bytes",
	}, []string{"zone_id", "zone_name"})

	cfThreatsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_threats_total",
		Help: "Total number of threats blocked",
	}, []string{"zone_id", "zone_name"})

	cfThreatsByCountry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_threats_by_country_total",
		Help: "Threats by country",
	}, []string{"zone_id", "zone_name", "country"})

	cfThreatsByType = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_threats_by_type_total",
		Help: "Threats by type",
	}, []string{"zone_id", "zone_name", "type"})

	cfPageviewsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_pageviews_total",
		Help: "Total number of pageviews",
	}, []string{"zone_id", "zone_name"})

	cfUniquesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_unique_visitors_total",
		Help: "Total unique visitors",
	}, []string{"zone_id", "zone_name"})

	cfSSLRequestsEncrypted = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_ssl_requests_encrypted_total",
		Help: "Total encrypted (HTTPS) requests",
	}, []string{"zone_id", "zone_name"})

	cfSSLRequestsUnencrypted = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_ssl_requests_unencrypted_total",
		Help: "Total unencrypted (HTTP) requests",
	}, []string{"zone_id", "zone_name"})

	cfScrapeSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_scrape_success",
		Help: "1 if the last scrape was successful, 0 otherwise",
	}, []string{"zone_id", "zone_name"})

	cfLastScrapeTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cloudflare_last_scrape_timestamp",
		Help: "Unix timestamp of the last successful scrape",
	}, []string{"zone_id", "zone_name"})
)

// ── Cloudflare client ───────────────────────────────────────────────────────

type CFClient struct {
	apiToken string
	http     *http.Client
}

func NewCFClient(token string) *CFClient {
	return &CFClient{
		apiToken: token,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *CFClient) get(path string, target interface{}) error {
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare API returned status %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func (c *CFClient) GetZones() ([]Zone, error) {
	var result ZoneListResponse
	if err := c.get("/zones?per_page=50&status=active", &result); err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("cloudflare API returned success=false for zones")
	}
	return result.Result, nil
}

// GetAnalytics uses the GraphQL Analytics API (the old REST endpoint is deprecated).
// sinceMinutes is capped at 4320 (3 days) — the maximum window for httpRequests1hGroups
// on the free tier. It queries all hourly buckets and sums them client-side.
func (c *CFClient) GetAnalytics(zoneID string, sinceMinutes int) (*HourSum, int64, error) {
	now := time.Now().UTC()
	// Cloudflare free tier: httpRequests1hGroups max window is 3 days (4320 min)
	if sinceMinutes > 4320 {
		sinceMinutes = 4320
	}
	since := now.Add(-time.Duration(sinceMinutes) * time.Minute).Format(time.RFC3339)
	until := now.Format(time.RFC3339)

	query := fmt.Sprintf(`{
		"query": "{ viewer { zones(filter: {zoneTag: \"%s\"}) { httpRequests1hGroups(limit: 10000, filter: {datetime_geq: \"%s\", datetime_leq: \"%s\"}) { sum { requests bytes cachedRequests cachedBytes pageViews threats encryptedBytes encryptedRequests countryMap { clientCountryName requests bytes threats } responseStatusMap { edgeResponseStatus requests } threatPathingMap { threatPathingName requests } } uniq { uniques } } } } }"
	}`, zoneID, since, until)

	req, err := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", bytes.NewBufferString(query))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("graphql API returned status %d", resp.StatusCode)
	}

	var gqlResp GraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return nil, 0, fmt.Errorf("failed to decode GraphQL response: %w", err)
	}
	if len(gqlResp.Errors) > 0 {
		return nil, 0, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}
	if len(gqlResp.Data.Viewer.Zones) == 0 {
		return nil, 0, fmt.Errorf("no zone data in GraphQL response")
	}

	// Sum all hourly buckets into a single total
	totals := &HourSum{}
	var uniques int64
	countryMap := map[string]*CountryEntry{}
	statusMap := map[int]int64{}
	threatMap := map[string]int64{}

	for _, group := range gqlResp.Data.Viewer.Zones[0].Groups {
		s := group.Sum
		totals.Requests += s.Requests
		totals.Bytes += s.Bytes
		totals.CachedRequests += s.CachedRequests
		totals.CachedBytes += s.CachedBytes
		totals.PageViews += s.PageViews
		totals.Threats += s.Threats
		totals.EncryptedBytes += s.EncryptedBytes
		totals.EncryptedRequests += s.EncryptedRequests
		uniques += group.Uniq.Uniques

		for _, c := range s.CountryMap {
			if e, ok := countryMap[c.ClientCountryName]; ok {
				e.Requests += c.Requests
				e.Bytes += c.Bytes
				e.Threats += c.Threats
			} else {
				entry := c
				countryMap[c.ClientCountryName] = &entry
			}
		}
		for _, r := range s.ResponseStatusMap {
			statusMap[r.EdgeResponseStatus] += r.Requests
		}
		for _, t := range s.ThreatPathingMap {
			threatMap[t.ThreatPathingName] += t.Requests
		}
	}

	// Flatten back into slices
	for name, entry := range countryMap {
		totals.CountryMap = append(totals.CountryMap, CountryEntry{
			ClientCountryName: name,
			Requests:          entry.Requests,
			Bytes:             entry.Bytes,
			Threats:           entry.Threats,
		})
	}
	for status, count := range statusMap {
		totals.ResponseStatusMap = append(totals.ResponseStatusMap, StatusEntry{
			EdgeResponseStatus: status,
			Requests:           count,
		})
	}
	for name, count := range threatMap {
		totals.ThreatPathingMap = append(totals.ThreatPathingMap, ThreatEntry{
			ThreatPathingName: name,
			Requests:          count,
		})
	}

	return totals, uniques, nil
}

// ── Scrape logic ────────────────────────────────────────────────────────────

func scrape(client *CFClient, sinceMinutes int) {
	zones, err := client.GetZones()
	if err != nil {
		log.Printf("ERROR: failed to list zones: %v", err)
		return
	}

	log.Printf("Scraping %d zone(s)...", len(zones))

	for _, zone := range zones {
		totals, uniques, err := client.GetAnalytics(zone.ID, sinceMinutes)
		if err != nil {
			log.Printf("ERROR: failed to get analytics for zone %s (%s): %v", zone.Name, zone.ID, err)
			cfScrapeSuccess.WithLabelValues(zone.ID, zone.Name).Set(0)
			continue
		}

		zid := zone.ID
		zname := zone.Name

		cfRequestsTotal.WithLabelValues(zid, zname).Set(float64(totals.Requests))
		cfRequestsCached.WithLabelValues(zid, zname).Set(float64(totals.CachedRequests))
		cfRequestsUncached.WithLabelValues(zid, zname).Set(float64(totals.Requests - totals.CachedRequests))

		if totals.Requests > 0 {
			cfRequestsCacheHitRatio.WithLabelValues(zid, zname).Set(float64(totals.CachedRequests) / float64(totals.Requests))
		} else {
			cfRequestsCacheHitRatio.WithLabelValues(zid, zname).Set(0)
		}

		for _, s := range totals.ResponseStatusMap {
			cfRequestsByStatus.WithLabelValues(zid, zname, strconv.Itoa(s.EdgeResponseStatus)).Set(float64(s.Requests))
		}
		for _, c := range totals.CountryMap {
			cfRequestsByCountry.WithLabelValues(zid, zname, c.ClientCountryName).Set(float64(c.Requests))
		}

		cfBandwidthTotal.WithLabelValues(zid, zname).Set(float64(totals.Bytes))
		cfBandwidthCached.WithLabelValues(zid, zname).Set(float64(totals.CachedBytes))
		cfBandwidthUncached.WithLabelValues(zid, zname).Set(float64(totals.Bytes - totals.CachedBytes))

		cfThreatsTotal.WithLabelValues(zid, zname).Set(float64(totals.Threats))
		for _, c := range totals.CountryMap {
			if c.Threats > 0 {
				cfThreatsByCountry.WithLabelValues(zid, zname, c.ClientCountryName).Set(float64(c.Threats))
			}
		}
		for _, t := range totals.ThreatPathingMap {
			cfThreatsByType.WithLabelValues(zid, zname, t.ThreatPathingName).Set(float64(t.Requests))
		}

		cfPageviewsTotal.WithLabelValues(zid, zname).Set(float64(totals.PageViews))
		cfUniquesTotal.WithLabelValues(zid, zname).Set(float64(uniques))

		cfSSLRequestsEncrypted.WithLabelValues(zid, zname).Set(float64(totals.EncryptedRequests))
		cfSSLRequestsUnencrypted.WithLabelValues(zid, zname).Set(float64(totals.Requests - totals.EncryptedRequests))

		cfScrapeSuccess.WithLabelValues(zid, zname).Set(1)
		cfLastScrapeTime.WithLabelValues(zid, zname).Set(float64(time.Now().Unix()))

		cacheRatio := 0.0
		if totals.Requests > 0 {
			cacheRatio = float64(totals.CachedRequests) / float64(totals.Requests) * 100
		}
		log.Printf("  ✓ %s — req: %d, threats: %d, bandwidth: %d bytes, cache: %.1f%%",
			zone.Name, totals.Requests, totals.Threats, totals.Bytes, cacheRatio)
	}
}

// ── Main ────────────────────────────────────────────────────────────────────

func main() {
	apiToken := os.Getenv("CF_API_TOKEN")
	if apiToken == "" {
		log.Fatal("CF_API_TOKEN environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9199"
	}

	intervalStr := os.Getenv("SCRAPE_INTERVAL_SECONDS")
	intervalSecs := 60
	if intervalStr != "" {
		if v, err := strconv.Atoi(intervalStr); err == nil && v > 0 {
			intervalSecs = v
		}
	}

	// Cloudflare free tier: data window in minutes (1440 = 24h)
	sinceStr := os.Getenv("CF_SINCE_MINUTES")
	sinceMinutes := 1440
	if sinceStr != "" {
		if v, err := strconv.Atoi(sinceStr); err == nil && v > 0 {
			sinceMinutes = v
		}
	}

	// Register all metrics
	prometheus.MustRegister(
		cfRequestsTotal, cfRequestsCached, cfRequestsUncached, cfRequestsCacheHitRatio,
		cfRequestsByStatus, cfRequestsByCountry,
		cfBandwidthTotal, cfBandwidthCached, cfBandwidthUncached,
		cfThreatsTotal, cfThreatsByCountry, cfThreatsByType,
		cfPageviewsTotal, cfUniquesTotal,
		cfSSLRequestsEncrypted, cfSSLRequestsUnencrypted,
		cfScrapeSuccess, cfLastScrapeTime,
	)

	client := NewCFClient(apiToken)

	log.Printf("Cloudflare Prometheus Exporter starting on :%s", port)
	log.Printf("Scrape interval: %ds | Analytics window: %dm", intervalSecs, sinceMinutes)

	// Initial scrape immediately on startup
	scrape(client, sinceMinutes)

	// Then scrape on interval
	go func() {
		ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
		for range ticker.C {
			scrape(client, sinceMinutes)
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
