// Copyright 2026 Query Farm LLC - https://query.farm

// Package mockrep is an embedded HTTP server that serves canned, normalized
// threat-intel reputation JSON. It is shared by the Go unit tests (httptest)
// and the standalone cmd/mockserver binary used by the haybarn SQL E2E.
//
// It serves a single endpoint, GET /reputation?indicator=..., mirroring the
// normalized reputation shape the worker consumes:
//
//	indicator=185.220.101.1 (or other known-bad) -> malicious=true verdict
//	indicator=93.184.216.34 (or other known-good) -> malicious=false verdict
//	indicator=<anything else>                     -> HTTP 404 (unknown)
//
// When constructed with an API key, every request must present a matching
// X-API-Key header or the server returns HTTP 401.
package mockrep

import (
	"encoding/json"
	"net/http"
)

// Handler returns an http.Handler serving canned reputation JSON at
// /reputation. If apiKey is non-empty, requests must carry a matching
// X-API-Key header.
func Handler(apiKey string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/reputation", func(w http.ResponseWriter, r *http.Request) {
		if apiKey != "" && r.Header.Get("X-API-Key") != apiKey {
			http.Error(w, `{"error":"missing or invalid api key"}`, http.StatusUnauthorized)
			return
		}
		ind := r.URL.Query().Get("indicator")
		if ind == "" {
			http.Error(w, `{"error":"missing indicator parameter"}`, http.StatusBadRequest)
			return
		}
		rec, ok := byIndicator[ind]
		if !ok {
			http.Error(w, `{"error":"indicator not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	})
	return mux
}
