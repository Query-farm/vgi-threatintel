// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Query-farm/vgi-threatintel/internal/mockrep"
)

// newMock returns a Client pointed at a fresh in-process mock reputation server
// (no api key), plus a cleanup func.
func newMock(t *testing.T) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(mockrep.Handler(""))
	c := NewClient(srv.URL+"/reputation", "", DefaultTimeout)
	return c, srv.Close
}

func TestReputation_Malicious(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	row, err := c.Reputation(context.Background(), "185.220.101.1")
	if err != nil {
		t.Fatalf("Reputation: %v", err)
	}
	if row == nil {
		t.Fatal("Reputation returned nil row for a known indicator")
	}
	if !row.Malicious {
		t.Errorf("Malicious = false, want true")
	}
	if row.Score == nil || *row.Score != 91.5 {
		t.Errorf("Score = %v, want 91.5", row.Score)
	}
	if len(row.Categories) == 0 {
		t.Errorf("Categories empty, want non-empty (e.g. c2)")
	}
	if row.Type != "ipv4" {
		t.Errorf("Type = %q, want ipv4", row.Type)
	}
	if row.Source != "demo-feed" {
		t.Errorf("Source = %q, want demo-feed", row.Source)
	}
}

func TestReputation_Clean(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	row, err := c.Reputation(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("Reputation: %v", err)
	}
	if row == nil {
		t.Fatal("nil row for a known-clean indicator")
	}
	if row.Malicious {
		t.Errorf("Malicious = true, want false")
	}
	// The clean record has a null score in the source -> nil pointer.
	if row.Score != nil {
		t.Errorf("Score = %v, want nil (source returned null)", *row.Score)
	}
}

func TestReputation_Unknown404(t *testing.T) {
	c, cleanup := newMock(t)
	defer cleanup()

	// An unknown but well-formed indicator: 404 -> (nil, nil), not an error.
	row, err := c.Reputation(context.Background(), "203.0.113.99")
	if err != nil {
		t.Fatalf("unknown indicator should not error, got %v", err)
	}
	if row != nil {
		t.Errorf("unknown indicator should yield nil row, got %+v", row)
	}
}

func TestReputation_ErrorStatuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"server-error", http.StatusInternalServerError},
		{"rate-limited", http.StatusTooManyRequests},
		{"bad-request", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", tc.status)
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "", DefaultTimeout)
			if _, err := c.Reputation(context.Background(), "1.2.3.4"); err == nil {
				t.Errorf("expected error for HTTP %d, got nil", tc.status)
			}
		})
	}
}

func TestReputation_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "", DefaultTimeout)
	if _, err := c.Reputation(context.Background(), "1.2.3.4"); err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestReputation_APIKeyEnforced(t *testing.T) {
	// The mock requires the key; a client without it gets a 401 -> error.
	srv := httptest.NewServer(mockrep.Handler("secret-key"))
	defer srv.Close()

	noKey := NewClient(srv.URL+"/reputation", "", DefaultTimeout)
	if _, err := noKey.Reputation(context.Background(), "185.220.101.1"); err == nil {
		t.Error("expected auth error without api_key, got nil")
	}

	withKey := NewClient(srv.URL+"/reputation", "secret-key", DefaultTimeout)
	row, err := withKey.Reputation(context.Background(), "185.220.101.1")
	if err != nil {
		t.Fatalf("with correct key: %v", err)
	}
	if row == nil || !row.Malicious {
		t.Errorf("with correct key, expected a malicious verdict, got %+v", row)
	}
}

func TestReputation_TimeoutHonored(t *testing.T) {
	// A short timeout against a slow server should fail rather than hang.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "", 20*time.Millisecond)
	if _, err := c.Reputation(context.Background(), "1.2.3.4"); err == nil {
		t.Error("expected timeout error, got nil")
	}
}
