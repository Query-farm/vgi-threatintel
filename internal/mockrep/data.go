// Copyright 2026 Query Farm LLC - https://query.farm

package mockrep

// repRecord mirrors the worker's normalized reputation JSON shape. score is a
// pointer so a record can express "no numeric score" (JSON null).
type repRecord struct {
	Indicator  string   `json:"indicator"`
	Type       string   `json:"type"`
	Malicious  bool     `json:"malicious"`
	Score      *float64 `json:"score"`
	Categories []string `json:"categories"`
	Source     string   `json:"source"`
	LastSeen   string   `json:"last_seen"`
}

func f(v float64) *float64 { return &v }

// byIndicator indexes the canned verdicts served by the /reputation lookup.
// Anything not present here returns 404 (unknown indicator).
var byIndicator = map[string]repRecord{
	// Known-malicious IPv4 (a Tor exit / C2-shaped record).
	"185.220.101.1": {
		Indicator:  "185.220.101.1",
		Type:       "ipv4",
		Malicious:  true,
		Score:      f(91.5),
		Categories: []string{"c2", "tor-exit", "scanner"},
		Source:     "demo-feed",
		LastSeen:   "2026-06-01T12:00:00Z",
	},
	// Known-malicious domain.
	"malware-c2.example": {
		Indicator:  "malware-c2.example",
		Type:       "domain",
		Malicious:  true,
		Score:      f(88.0),
		Categories: []string{"malware", "phishing"},
		Source:     "demo-feed",
		LastSeen:   "2026-05-20T09:30:00Z",
	},
	// Known-malicious file hash (sha256).
	"44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f": {
		Indicator:  "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
		Type:       "sha256",
		Malicious:  true,
		Score:      f(99.0),
		Categories: []string{"trojan"},
		Source:     "demo-feed",
		LastSeen:   "2026-04-15T00:00:00Z",
	},
	// Known-clean IPv4 (e.g. example.com's address). No score from the source.
	"93.184.216.34": {
		Indicator:  "93.184.216.34",
		Type:       "ipv4",
		Malicious:  false,
		Score:      nil,
		Categories: []string{},
		Source:     "demo-feed",
		LastSeen:   "",
	},
	// Known-clean domain.
	"good.example": {
		Indicator:  "good.example",
		Type:       "domain",
		Malicious:  false,
		Score:      f(2.0),
		Categories: []string{},
		Source:     "demo-feed",
		LastSeen:   "2026-06-10T00:00:00Z",
	},
}
