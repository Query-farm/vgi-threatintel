// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the default reputation endpoint. There is no single neutral
// public reputation API that needs no key, so this points at a documented,
// self-hostable normalized-reputation endpoint shape (see README). Callers
// override it with the base_url named option — the E2E suite points it at the
// local mock, and production deployments point it at an adapter in front of a
// real feed (OTX AlienVault, abuse.ch URLhaus/ThreatFox, VirusTotal).
//
// The worker speaks a SIMPLE NORMALIZED reputation JSON (see RepResponse). Real
// sources have different shapes and auth; document/implement an adapter behind
// this same GET interface rather than teaching the worker each source's schema.
const DefaultBaseURL = "https://reputation.example/reputation"

// DefaultTimeout bounds an HTTP call when the timeout_ms option is unset or
// non-positive, so a slow or unreachable endpoint fails fast rather than
// hanging DuckDB.
const DefaultTimeout = 15 * time.Second

// Client queries a normalized reputation endpoint.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// NewClient builds a Client. An empty baseURL falls back to DefaultBaseURL; an
// empty apiKey means unauthenticated. A non-positive timeout falls back to
// DefaultTimeout.
func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: timeout},
	}
}

// RepRow is the flattened, SQL-friendly verdict for one indicator. A nil Score
// pointer means the source gave no numeric score, surfaced as SQL NULL.
type RepRow struct {
	Indicator  string
	Type       string
	Malicious  bool
	Score      *float64
	Categories []string
	Source     string
	LastSeen   string
}

// RepResponse is the SIMPLE NORMALIZED reputation JSON the worker consumes. An
// adapter in front of a real feed maps that feed's response into this shape.
//
//	{
//	  "indicator": "1.2.3.4",
//	  "type": "ipv4",
//	  "malicious": true,
//	  "score": 87.5,
//	  "categories": ["c2", "scanner"],
//	  "source": "demo-feed",
//	  "last_seen": "2026-06-01T00:00:00Z"
//	}
//
// score is optional (pointer): omitted/null → SQL NULL.
type RepResponse struct {
	Indicator  string   `json:"indicator"`
	Type       string   `json:"type"`
	Malicious  bool     `json:"malicious"`
	Score      *float64 `json:"score"`
	Categories []string `json:"categories"`
	Source     string   `json:"source"`
	LastSeen   string   `json:"last_seen"`
}

// Reputation looks up a single indicator. It returns:
//
//   - a row + nil error on a 200 hit;
//   - (nil, nil) on a 404 (unknown indicator) — the caller emits no rows;
//   - a non-nil error for any other non-2xx status (429 rate-limit, 4xx, 5xx)
//     or a malformed JSON body.
//
// Private/reserved IPs and unsupported indicator strings are handled by the
// caller before reaching the network; this method assumes a lookupable
// indicator.
func (c *Client) Reputation(ctx context.Context, indicator string) (*RepRow, error) {
	q := url.Values{}
	q.Set("indicator", indicator)

	full := c.BaseURL
	if enc := q.Encode(); enc != "" {
		sep := "?"
		if strings.Contains(full, "?") {
			sep = "&"
		}
		full = full + sep + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, fmt.Errorf("reputation: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		// Many feeds take the key as a header; an adapter can rename this. We
		// send a generic X-API-Key plus an apikey query mirror for sources that
		// expect it on the URL (the mock checks the header).
		req.Header.Set("X-API-Key", c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reputation: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("reputation: read response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// Unknown indicator: not an error, just no verdict.
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("reputation: authentication failed (HTTP %d); set or check api_key: %s",
			resp.StatusCode, snippet(body))
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("reputation: rate limited (HTTP 429); set an api_key or slow down: %s", snippet(body))
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("reputation: API error (HTTP %d): %s", resp.StatusCode, snippet(body))
	}

	var out RepResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("reputation: decode JSON response: %w", err)
	}

	row := projectReputation(indicator, out)
	return &row, nil
}

// projectReputation flattens a normalized RepResponse into a RepRow, filling in
// a locally-derived type if the source omitted one.
func projectReputation(indicator string, r RepResponse) RepRow {
	typ := strings.TrimSpace(r.Type)
	if typ == "" {
		typ = IndicatorType(indicator)
	}
	cats := r.Categories
	if cats == nil {
		cats = []string{}
	}
	return RepRow{
		Indicator:  indicator,
		Type:       typ,
		Malicious:  r.Malicious,
		Score:      r.Score,
		Categories: cats,
		Source:     r.Source,
		LastSeen:   r.LastSeen,
	}
}

// snippet trims and bounds an error-body excerpt so a huge or noisy upstream
// body doesn't bloat the surfaced error.
func snippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 256 {
		s = s[:256] + "…"
	}
	return s
}
