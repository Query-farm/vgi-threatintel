// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

// Shared helpers for the per-object discovery/description metadata that the
// vgi-lint strict profile (0.23.0) expects on EVERY function and table. Each
// function/table surfaces these in its FunctionMetadata.Tags:
//
//   - vgi.title (VGI124)           — human-friendly display name
//   - vgi.description_llm (VGI112) — concise prose aimed at LLMs
//   - vgi.description_md (VGI113)  — short Markdown description
//   - vgi.keywords (VGI126)        — comma-separated search terms/synonyms
//   - vgi.source_url (VGI128)      — link to the implementing source file
//
// sourceURL(file) builds the canonical GitHub blob URL (pinned to main) so every
// object points at exactly where it is implemented.

// sourceBase is the GitHub blob base for source files in this repo (pinned main).
const sourceBase = "https://github.com/Query-farm/vgi-threatintel/blob/main"

// sourceURL builds the implementation vgi.source_url for a repo-relative path,
// e.g. sourceURL("internal/threatworker/indicator.go").
func sourceURL(relativePath string) string {
	return sourceBase + "/" + relativePath
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

// objectTags builds the five standard per-object discovery/description tags for a
// function or table. relativePath is the implementing file relative to the repo
// root. Callers may add more entries to the returned map.
func objectTags(title, descriptionLLM, descriptionMD, keywords, relativePath string) map[string]string {
	return map[string]string{
		"vgi.title":           title,
		"vgi.description_llm": descriptionLLM,
		"vgi.description_md":  descriptionMD,
		"vgi.keywords":        keywords,
		"vgi.source_url":      sourceURL(relativePath),
	}
}
