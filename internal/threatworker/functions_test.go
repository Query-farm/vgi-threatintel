// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"net/http/httptest"
	"testing"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-threatintel/internal/mockrep"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// strCol builds a 1-row string array (optionally NULL) for a positional arg.
func strCol(t *testing.T, v string, null bool) arrow.Array {
	t.Helper()
	b := array.NewStringBuilder(memory.DefaultAllocator)
	defer b.Release()
	if null {
		b.AppendNull()
	} else {
		b.Append(v)
	}
	return b.NewArray()
}

func stringScalar(v string) arrow.Array {
	b := array.NewStringBuilder(memory.DefaultAllocator)
	defer b.Release()
	b.Append(v)
	return b.NewArray()
}

// argsWithBaseURL builds *vgi.Arguments with a single positional plus the
// base_url named option pointing at the in-process mock reputation server.
func argsWithBaseURL(pos arrow.Array, baseURL string) *vgi.Arguments {
	return &vgi.Arguments{
		Positional: []arrow.Array{pos},
		Named:      map[string]arrow.Array{"base_url": stringScalar(baseURL)},
	}
}

func mockBaseURL(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(mockrep.Handler(""))
	return srv.URL + "/reputation", srv.Close
}

func TestReputationFunction_Malicious(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &ReputationFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "185.220.101.1", false), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(st.Rows))
	}
	r := st.Rows[0]
	if !r.Malicious {
		t.Errorf("Malicious = false, want true")
	}
	if len(r.Categories) == 0 {
		t.Errorf("Categories empty, want non-empty")
	}
	if st.Done {
		t.Error("state should not be done before Process")
	}
}

func TestReputationFunction_Clean(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &ReputationFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "93.184.216.34", false), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 1 || st.Rows[0].Malicious {
		t.Fatalf("expected 1 clean row, got %+v", st.Rows)
	}
}

func TestReputationFunction_UnknownNoRows(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &ReputationFunction{}
	// Well-formed but unknown indicator (mock 404) -> no rows, no error.
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "203.0.113.5", false), base),
	})
	if err != nil {
		t.Fatalf("unknown indicator should not error: %v", err)
	}
	if len(st.Rows) != 0 {
		t.Errorf("unknown indicator should yield no rows, got %d", len(st.Rows))
	}
}

func TestReputationFunction_PrivateIPSkipped(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &ReputationFunction{}
	// A private IP must not be looked up at all -> no rows, no error.
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "10.0.0.1", false), base),
	})
	if err != nil {
		t.Fatalf("private IP should not error: %v", err)
	}
	if len(st.Rows) != 0 {
		t.Errorf("private IP should be skipped (0 rows), got %d", len(st.Rows))
	}
}

func TestReputationFunction_UnsupportedSkipped(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &ReputationFunction{}
	// An unsupported indicator (not an IP/domain/url/hash) -> no rows, no error.
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "not-an-indicator!!", false), base),
	})
	if err != nil {
		t.Fatalf("unsupported indicator should not error: %v", err)
	}
	if len(st.Rows) != 0 {
		t.Errorf("unsupported indicator should yield 0 rows, got %d", len(st.Rows))
	}
}

func TestReputationFunction_NullArgNoRows(t *testing.T) {
	base, cleanup := mockBaseURL(t)
	defer cleanup()

	f := &ReputationFunction{}
	st, err := f.NewState(&vgi.ProcessParams{
		Args: argsWithBaseURL(strCol(t, "", true), base),
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 0 {
		t.Errorf("NULL arg should yield no rows, got %d", len(st.Rows))
	}
}

func TestRegisterDoesNotPanic(t *testing.T) {
	// Registration triggers the SDK's gob-encodability check on table-function
	// state; this guards against re-introducing a non-encodable state field.
	w := vgi.NewWorker(vgi.WithCatalogName(CatalogName))
	Register(w)
}
