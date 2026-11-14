// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import "github.com/Query-farm/vgi-go/vgi"

// Composed example queries: each combines two or more of this worker's own
// objects in one realistic query. Every SQL string is defined ONCE here and
// referenced from the schema-level vgi.example_queries list AND from the example
// list of the object that drives the query (within its first five examples, the
// only ones the vgi-lint agent simulator shows), so the copies never drift.
// Exception: feedTypeCrossCheckExample needs a live reputation adapter, so it is
// schema-level only (see below).
//
// The reputation table function accepts only LITERAL arguments (DuckDB rejects
// LATERAL column parameters over a VGI table function), so the compositions are
// built around the offline scalars + the indicator_types view, plus one
// verdict-vs-classifier cross-check on a single reputation lookup.

// triageBatchSQL types a mixed batch of indicators, describes each type from the
// indicator_types view, and flags which rows are worth a reputation lookup.
// Offline and deterministic.
const triageBatchSQL = `WITH iocs(ioc) AS (
  VALUES ('185.220.101.1'), ('10.0.0.5'), ('malware-c2.example'),
         ('https://good.example/login'), ('44d88612fea8a8f36de82e1278abb02f'), ('not-an-indicator!!')
), typed AS (
  SELECT ioc,
         threatintel.main.indicator_type(ioc) AS kind,
         threatintel.main.is_private_ip(ioc) AS is_private
  FROM iocs
)
SELECT typed.ioc, typed.kind, t.description, typed.is_private,
       typed.kind IS NOT NULL AND NOT typed.is_private AS needs_lookup
FROM typed
LEFT JOIN threatintel.main.indicator_types AS t ON t.indicator_type = typed.kind
ORDER BY needs_lookup DESC, typed.ioc`

// triageBatchExample: driven by indicator_type.
var triageBatchExample = vgi.CatalogExample{
	SQL: triageBatchSQL,
	Description: "Triage a mixed batch of indicators: classify each with indicator_type, " +
		"attach the type's description from the indicator_types view, flag private IPs with " +
		"is_private_ip, and mark which rows need a reputation lookup (4 of the 6 here: the " +
		"private 10.0.0.5 and the unrecognized string do not).",
}

// typeCoverageSQL counts a batch of indicators per supported type, listing every
// type from the indicator_types view (zero-count types included). Offline.
const typeCoverageSQL = `WITH iocs(ioc) AS (
  VALUES ('185.220.101.1'), ('8.8.8.8'), ('10.0.0.5'), ('malware-c2.example'),
         ('44d88612fea8a8f36de82e1278abb02f'),
         ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), ('not-an-indicator!!')
)
SELECT t.indicator_type, count(i.ioc) AS n_indicators
FROM threatintel.main.indicator_types AS t
LEFT JOIN iocs AS i ON threatintel.main.indicator_type(i.ioc) = t.indicator_type
GROUP BY t.indicator_type
ORDER BY t.indicator_type`

// typeCoverageExample: driven by the indicator_types view.
var typeCoverageExample = vgi.CatalogExample{
	SQL: typeCoverageSQL,
	Description: "Count a batch of indicators per IoC type, listing every type in the " +
		"indicator_types view (types absent from the batch show 0; the unrecognized string " +
		"matches no type and is not counted).",
}

// feedTypeCrossCheckSQL compares the type a reputation feed reports against the
// offline classifier, to catch an adapter that mislabels indicators. Needs a
// configured reputation adapter (base_url), so it is not offline.
const feedTypeCrossCheckSQL = `SELECT r.indicator, r.type AS feed_type,
       threatintel.main.indicator_type(r.indicator) AS offline_type,
       r.type = threatintel.main.indicator_type(r.indicator) AS types_agree
FROM threatintel.main.reputation('malware-c2.example',
       base_url := 'https://my-reputation-adapter.internal/reputation') AS r
ORDER BY r.indicator`

// feedTypeCrossCheckExample: driven by reputation, but schema-level ONLY. It
// needs a live adapter, and vgi-lint --execute runs every object-level example
// (VGI901 would flag the unreachable host), while schema-level lists are not
// executed. The same holds for the other backend-qualified reputation examples.
var feedTypeCrossCheckExample = vgi.CatalogExample{
	SQL: feedTypeCrossCheckSQL,
	Description: "Sanity-check a reputation adapter: compare the type the feed reports for " +
		"a looked-up indicator with the offline indicator_type classification (types_agree " +
		"is false when the adapter mislabels it). Requires a reachable base_url; returns no " +
		"rows when the feed does not know the indicator.",
}

// schemaExamples is the schema-level vgi.example_queries list (VGI506/VGI515):
// single-object examples first, then the composed ones.
var schemaExamples = []vgi.CatalogExample{
	{
		Description: "Classify an IPv4 address string into its indicator (IoC) type.",
		SQL:         "SELECT threatintel.main.indicator_type('8.8.8.8') AS kind",
	},
	{
		Description: "Flag a private/reserved (RFC1918) IP that should never be sent to an external reputation feed.",
		SQL:         "SELECT threatintel.main.is_private_ip('10.0.0.5') AS is_private",
	},
	{
		Description: "Enrich a single indicator against the configured reputation source, projecting the verdict fields.",
		SQL:         "SELECT indicator, malicious, score, categories FROM threatintel.main.reputation('1.2.3.4')",
	},
	{
		Description: "Look up an indicator against an explicit reputation adapter with an API key, keeping only the malicious flag, score, and categories.",
		SQL:         "SELECT malicious, score, categories FROM threatintel.main.reputation('evil.example.com', base_url := 'https://my-reputation-adapter.internal/reputation', api_key := 'YOUR_KEY')",
	},
	triageBatchExample,
	typeCoverageExample,
	feedTypeCrossCheckExample,
}

// SchemaExampleQueries is the JSON for the main schema's vgi.example_queries tag.
var SchemaExampleQueries = exampleQueriesJSON(schemaExamples)

// executableExamples are guaranteed-runnable {description, sql} examples
// (VGI509/VGI906). Every statement is catalog-qualified, self-contained, and
// re-runnable against an attached threatintel worker WITHOUT a live reputation
// backend: the scalars and the indicator_types view are pure/offline, and the
// reputation calls use a private/reserved IP and an unsupported string, both of
// which are triaged to zero rows before any network call. expected_result is
// omitted deliberately.
var executableExamples = []vgi.CatalogExample{
	{
		Description: "Classify an IPv4 address as an indicator type.",
		SQL:         "SELECT threatintel.main.indicator_type('8.8.8.8') AS kind",
	},
	{
		Description: "Classify a 64-hex-character file hash as sha256.",
		SQL:         "SELECT threatintel.main.indicator_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') AS kind",
	},
	{
		Description: "Flag a private/reserved (RFC1918) IP that should not be looked up.",
		SQL:         "SELECT threatintel.main.is_private_ip('10.0.0.5') AS private",
	},
	{
		Description: "A routable public IP is not private (safe to enrich).",
		SQL:         "SELECT threatintel.main.is_private_ip('8.8.8.8') AS private",
	},
	{
		Description: "A private/reserved IP is triaged to zero reputation rows before any network call.",
		SQL:         "SELECT count(*) AS n FROM threatintel.main.reputation('10.0.0.5')",
	},
	{
		Description: "An unsupported indicator string yields zero reputation rows (no lookup).",
		SQL:         "SELECT count(*) AS n FROM threatintel.main.reputation('not-an-indicator')",
	},
	triageBatchExample,
}

// ExecutableExamples is the JSON for the main schema's vgi.executable_examples tag.
var ExecutableExamples = exampleQueriesJSON(executableExamples)
