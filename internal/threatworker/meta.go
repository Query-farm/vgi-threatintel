// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"encoding/json"

	"github.com/Query-farm/vgi-go/vgi"
)

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

// exampleQueriesJSON serializes a function's Examples into the described-list
// form ([{"description":...,"sql":...}]) that the vgi.example_queries tag
// requires (VGI515). The native duckdb_functions().examples carrier that the
// FunctionMetadata.Examples field feeds drops the per-example descriptions, so
// each function ALSO surfaces this tag — kept byte-identical to its Examples so
// the two never drift, and so every example carries a human-readable description.
func exampleQueriesJSON(examples []vgi.CatalogExample) string {
	type describedExample struct {
		Description string `json:"description"`
		SQL         string `json:"sql"`
	}
	out := make([]describedExample, len(examples))
	for i, e := range examples {
		out[i] = describedExample{Description: e.Description, SQL: e.SQL}
	}
	b, _ := json.Marshal(out)
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
