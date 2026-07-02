// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import "encoding/json"

// Shared helpers for the per-object discovery/description metadata that the
// vgi-lint strict profile expects on EVERY function and table. Each
// function/table surfaces these in its FunctionMetadata.Tags:
//
//   - vgi.title (VGI124)           — human-friendly display name
//   - vgi.doc_llm (VGI112)         — Markdown narrative aimed at LLMs/agents
//   - vgi.doc_md (VGI113)          — Markdown narrative for human docs
//   - vgi.keywords (VGI126/VGI138) — search terms/synonyms as a JSON array
//
// Per-object vgi.source_url is intentionally NOT set here: provenance lives only
// on the catalog object (VGI139 — per-object source links are redundant).

// keywordsJSON serializes a list of keyword strings into the JSON-array form
// that vgi.keywords requires (VGI138), e.g. ["ipv4","domain"]. The encoding of a
// plain []string never fails, so the error is dropped.
func keywordsJSON(keywords []string) string {
	b, _ := json.Marshal(keywords)
	return string(b)
}

// mergeTags returns base with every key/value from extra added (extra wins on a
// key collision). It mutates and returns base for convenience.
func mergeTags(base, extra map[string]string) map[string]string {
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// ExecutableExamples is a JSON list of guaranteed-runnable {description, sql}
// examples (VGI509/VGI906). Every statement is catalog-qualified, self-contained,
// and re-runnable against an attached threatintel worker WITHOUT a live
// reputation backend: the scalars are pure/offline, and the reputation calls use
// a private/reserved IP and an unsupported string, both of which are triaged to
// zero rows before any network call. expected_result is omitted deliberately.
const ExecutableExamples = `[
  {
    "description": "Classify an IPv4 address as an indicator type.",
    "sql": "SELECT threatintel.main.indicator_type('8.8.8.8') AS kind"
  },
  {
    "description": "Classify a 64-hex-character file hash as sha256.",
    "sql": "SELECT threatintel.main.indicator_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') AS kind"
  },
  {
    "description": "Flag a private/reserved (RFC1918) IP that should not be looked up.",
    "sql": "SELECT threatintel.main.is_private_ip('10.0.0.5') AS private"
  },
  {
    "description": "A routable public IP is not private (safe to enrich).",
    "sql": "SELECT threatintel.main.is_private_ip('8.8.8.8') AS private"
  },
  {
    "description": "A private/reserved IP is triaged to zero reputation rows before any network call.",
    "sql": "SELECT count(*) AS n FROM threatintel.main.reputation('10.0.0.5')"
  },
  {
    "description": "An unsupported indicator string yields zero reputation rows (no lookup).",
    "sql": "SELECT count(*) AS n FROM threatintel.main.reputation('not-an-indicator')"
  }
]`

// objectTags builds the standard per-object discovery/description tags for a
// function or table. keywords is a list of search terms/synonyms, serialized to
// the JSON-array form vgi.keywords requires (VGI138). category (VGI413) must
// name one of the schema's vgi.categories registry entries. Per-object
// vgi.source_url is deliberately omitted: provenance is catalog-level only
// (VGI139). Callers may add more entries to the returned map.
func objectTags(title, descriptionLLM, descriptionMD, category string, keywords []string) map[string]string {
	return map[string]string{
		"vgi.title":    title,
		"vgi.doc_llm":  descriptionLLM,
		"vgi.doc_md":   descriptionMD,
		"vgi.category": category,
		"vgi.keywords": keywordsJSON(keywords),
	}
}
