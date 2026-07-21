// Copyright 2026 Query Farm LLC - https://query.farm

// Command vgi-threatintel-worker is a VGI worker that enriches cyber indicators
// (IPs, domains, URLs, file hashes) against a threat-intelligence reputation
// source and classifies them offline, exposed as DuckDB SQL functions. It is a
// defensive SOC / threat-hunting tool intended for AUTHORIZED use, and composes
// with sibling workers (vgi-ioc / vgi-cve / vgi-yara / vgi-sigma). It speaks the
// VGI protocol over stdio.
package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-threatintel/internal/threatworker"
)

func main() {
	// Accept --http for HTTP transport and --unix for the AF_UNIX launcher
	// transport; default is stdio. Unknown launcher flags are tolerated (the
	// VGI extension varies argv to key its worker cache), so we filter to flags
	// we actually define before parsing.
	httpMode := flag.Bool("http", false, "Run as an HTTP server instead of stdio")
	unixPath := flag.String("unix", "", "Serve the AF_UNIX launcher transport on this socket path instead of stdio")
	logFlags := vgi.RegisterLoggingFlags(flag.CommandLine)
	_ = flag.CommandLine.Parse(filterKnownFlags(os.Args[1:], map[string]bool{
		"log-level":  true,
		"log-format": true,
		"log-logger": true,
		"unix":       true,
	}))
	if err := logFlags.Apply(); err != nil {
		log.Fatalf("logging flags: %v", err)
	}

	sourceURL := "https://github.com/Query-farm/vgi-threatintel"
	w := vgi.NewWorker(
		vgi.WithCatalogName(threatworker.CatalogName),
		vgi.WithCatalogComment("Enrich cyber indicators against threat-intel reputation sources; classify offline"),
		vgi.WithCatalogTags(map[string]string{
			"source":    "vgi-threatintel",
			"vgi.title": "Threat-Intel Indicator Enrichment",
			"vgi.keywords": `["threat intelligence","threat intel","indicators","ioc","ip",` +
				`"domain","url","file hash","reputation","malicious","enrichment",` +
				`"classification","soc","threat hunting","incident response","cyber",` +
				`"defensive security"]`,
			// VGI152: agent test suite (simulate). Every reference_sql uses the
			// OFFLINE, deterministic path only — the classification scalars and
			// the reputation triage that returns zero rows for private/reserved
			// IPs and unsupported strings BEFORE any network call — so the suite
			// grades reproducibly with no live reputation backend.
			"vgi.agent_test_tasks": `[` +
				`{"name":"type_an_ipv4_indicator",` +
				`"prompt":"What indicator type does the string 8.8.8.8 classify as?",` +
				`"reference_sql":"SELECT threatintel.main.indicator_type('8.8.8.8') AS kind;",` +
				`"ignore_column_names":true},` +
				`{"name":"type_a_sha256_hash",` +
				`"prompt":"Classify the indicator e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 into its indicator type.",` +
				`"reference_sql":"SELECT threatintel.main.indicator_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') AS kind;",` +
				`"ignore_column_names":true},` +
				// These two tasks ask "which IP" (returning a single, unambiguous
				// IP string) rather than a yes/no question: a bare boolean/yes-no
				// prompt lets the analyst answer in many equivalent-but-unequal
				// shapes ('yes' vs TRUE vs 1), which strict reference-compare
				// grading (VGI920) rejects. A specific-string answer mirrors the
				// reliably-passing "classify into its type" tasks and exercises
				// is_private_ip as the intended per-row triage filter.
				`{"name":"private_ip_must_not_be_looked_up",` +
				`"prompt":"You have two candidate IP addresses to enrich: 10.0.0.5 and 8.8.8.8. Which one must NOT be sent to an external reputation feed because it is a private or reserved address? Return only that IP address.",` +
				`"reference_sql":"SELECT ip FROM (VALUES ('10.0.0.5'), ('8.8.8.8')) AS t(ip) WHERE threatintel.main.is_private_ip(ip);",` +
				`"ignore_column_names":true},` +
				`{"name":"public_ip_is_safe_to_enrich",` +
				`"prompt":"Of the IP addresses 10.0.0.5 and 8.8.8.8, which is a routable public address that is safe to look up against an external reputation feed? Return only that IP address.",` +
				`"reference_sql":"SELECT ip FROM (VALUES ('10.0.0.5'), ('8.8.8.8')) AS t(ip) WHERE NOT threatintel.main.is_private_ip(ip);",` +
				`"ignore_column_names":true},` +
				`{"name":"private_ip_yields_zero_reputation_rows",` +
				`"prompt":"How many reputation rows are returned for the private IP address 10.0.0.5 (which is triaged out before any lookup)?",` +
				`"reference_sql":"SELECT count(*) AS n FROM threatintel.main.reputation('10.0.0.5');",` +
				`"ignore_column_names":true},` +
				`{"name":"count_supported_indicator_types",` +
				`"prompt":"Using the worker's indicator_types reference view, how many distinct indicator (IoC) types does this worker recognize?",` +
				`"reference_sql":"SELECT count(*) AS n FROM threatintel.main.indicator_types;",` +
				`"ignore_column_names":true},` +
				`{"name":"canonical_example_for_sha256",` +
				`"prompt":"According to the indicator_types reference view, what is the canonical example value for the sha256 indicator type?",` +
				`"reference_sql":"SELECT example FROM threatintel.main.indicator_types WHERE indicator_type = 'sha256';",` +
				`"ignore_column_names":true}` +
				`]`,
			"vgi.doc_llm": "Defensive threat-intelligence worker for cyber indicators (IoCs). " +
				"Offline scalars classify an indicator string as ipv4/ipv6/domain/url/md5/sha1/sha256 " +
				"(indicator_type) and flag private/reserved IPs that should not be looked up " +
				"(is_private_ip); the reputation table function enriches one indicator against a " +
				"threat-intel reputation source, returning at most one verdict row with a malicious " +
				"flag, score, categories, source, and last_seen. Use to triage and enrich IPs, " +
				"domains, URLs, and file hashes in SQL during SOC / threat-hunting work (AUTHORIZED use only).",
			"vgi.doc_md": "# Threat-Intel Indicator Enrichment\n\n" +
				"**Enrich and classify cyber threat indicators — IPs, domains, URLs, and file " +
				"hashes — against threat-intelligence reputation feeds directly in SQL.** This VGI " +
				"worker turns DuckDB into a threat-hunting and indicator-of-compromise (IoC) triage " +
				"engine: parse and type any indicator offline, screen out private/reserved IPs, then " +
				"look up reputation verdicts (malicious flag, score, categories, source) from a " +
				"pluggable feed — all without leaving your query.\n\n" +
				"It is built for SOC analysts, threat hunters, incident responders, and detection " +
				"engineers who want to enrich and prioritize indicators in place rather than juggling " +
				"separate enrichment scripts and spreadsheets. The worker is a **defensive** security " +
				"tool intended for **authorized use only**, and it composes with sibling VGI workers " +
				"such as `vgi-ioc`, `vgi-cve`, `vgi-yara`, and `vgi-sigma` to build a full SQL-native " +
				"threat-intelligence stack.\n\n" +
				"Under the hood the worker is a standalone process that [DuckDB](https://duckdb.org) " +
				"attaches over Apache Arrow via the [vgi-go SDK](https://github.com/Query-farm/vgi-go). " +
				"It deliberately hard-codes no single feed: it speaks a simple **normalized reputation " +
				"JSON** over `GET {base_url}?indicator=<value>`, so you point it at any adapter that " +
				"maps a provider's response into that shape. Popular feeds plug in behind this one " +
				"interface, including [AlienVault OTX](https://otx.alienvault.com/api), " +
				"[abuse.ch URLhaus](https://urlhaus-api.abuse.ch/), " +
				"[abuse.ch ThreatFox](https://threatfox.abuse.ch/api/), and " +
				"[VirusTotal](https://docs.virustotal.com/) — each with its own API key, rate limits, " +
				"and terms of use.\n\n" +
				"## SQL functions\n\n" +
				"Two offline scalars triage indicators with **no network call**: `indicator_type` " +
				"classifies a string as `ipv4`/`ipv6`/`domain`/`url`/`md5`/`sha1`/`sha256` (or NULL " +
				"when unrecognized), and `is_private_ip` flags private/reserved IP addresses that " +
				"should never be sent to an external feed. The `reputation` table function then " +
				"enriches a single indicator against the configured source — selected with `base_url` " +
				"plus optional `api_key` and `timeout_ms` — and returns at most one verdict row with " +
				"the `malicious` flag, `score`, `categories`, `source`, and `last_seen`.\n\n" +
				"A typical workflow first triages a whole column of indicators with the two offline " +
				"scalars — `indicator_type` to classify each observable and `is_private_ip` to screen " +
				"out internal hosts — and then enriches only the survivors with " +
				"`reputation('1.2.3.4')`. Private/reserved IPs and unknown " +
				"indicators return zero rows with no error, so enrichment stays cheap and safe. See " +
				"the [vgi-threatintel source repository](https://github.com/Query-farm/vgi-threatintel) " +
				"for adapter examples and the full normalized-feed contract.",
			"vgi.author":             "Query.Farm",
			"vgi.copyright":          "Copyright 2026 Query Farm LLC - https://query.farm",
			"vgi.license":            "MIT",
			"vgi.support_contact":    "https://github.com/Query-farm/vgi-threatintel/issues",
			"vgi.support_policy_url": "https://github.com/Query-farm/vgi-threatintel/blob/main/README.md",
		}),
		vgi.WithCatalogInfo(vgi.CatalogInfo{
			Name:      threatworker.CatalogName,
			SourceURL: &sourceURL,
		}),
		vgi.WithSchemaComments(map[string]string{
			"main": "Threat-intel indicator classification and reputation-enrichment functions.",
		}),
		vgi.WithSchemaTags(map[string]map[string]string{
			"main": {
				"vgi.title": "Threat-Intel — main",
				"vgi.keywords": `["threat intel","indicator","ioc","indicator_type",` +
					`"is_private_ip","reputation","classify","enrich","ip","domain","url",` +
					`"file hash","malicious","soc","threat hunting"]`,
				// VGI123 classifying tags MUST use BARE keys (not vgi.-namespaced).
				"domain":   "security",
				"category": "threat-intelligence",
				"topic":    "indicator-enrichment",
				// VGI413: ordered category registry; each function carries a
				// matching vgi.category tag naming one of these.
				"vgi.categories": `[` +
					`{"name":"Offline Triage","description":"Pure, offline indicator classification and screening — type an IoC string and flag private/reserved IPs — with no network access, to route and prioritize indicators before spending reputation-API budget."},` +
					`{"name":"Reputation Enrichment","description":"Live lookups of a single indicator against a normalized threat-intel reputation source, returning a verdict row with a malicious flag, score, categories, source, and last_seen."}` +
					`]`,
				// Per-object vgi.source_url omitted (VGI139): provenance is
				// catalog-level only (set via WithCatalogInfo SourceURL).
				"vgi.doc_llm": "Threat-intel functions: classify an indicator's IoC type " +
					"(indicator_type), flag private/reserved IPs (is_private_ip), and enrich one " +
					"indicator against a reputation source (reputation table function).",
				"vgi.doc_md": "## `threatintel.main`\n\n" +
					"The single schema of the **threatintel** worker. It groups two " +
					"complementary capability families for working with cyber indicators " +
					"(IoCs) directly in SQL:\n\n" +
					"- **Offline triage** — pure, deterministic scalars that run with no " +
					"network access: classify an indicator string into its type and screen out " +
					"private/reserved IP addresses that should never be sent to an external feed.\n" +
					"- **Reputation enrichment** — a table function that looks up a single " +
					"indicator against a normalized threat-intel reputation source and returns a " +
					"verdict row (malicious flag, score, categories, source, last_seen).\n\n" +
					"The usual pattern is to triage a whole column of indicators with the " +
					"offline scalars first, then enrich only the survivors so lookups stay " +
					"cheap and safe.",
				// VGI506/VGI515 representative example queries as a described list
				// ([{description, sql}]) so every example carries a human-readable
				// description. Uses explicit projections (VGI514, no bare SELECT *).
				// The two reputation examples are backend-qualified and not
				// executed by the offline linter run.
				"vgi.example_queries": `[` +
					`{"description":"Classify an IPv4 address string into its indicator (IoC) type.",` +
					`"sql":"SELECT threatintel.main.indicator_type('8.8.8.8') AS kind"},` +
					`{"description":"Flag a private/reserved (RFC1918) IP that should never be sent to an external reputation feed.",` +
					`"sql":"SELECT threatintel.main.is_private_ip('10.0.0.5') AS is_private"},` +
					`{"description":"Enrich a single indicator against the configured reputation source, projecting the verdict fields.",` +
					`"sql":"SELECT indicator, malicious, score, categories FROM threatintel.main.reputation('1.2.3.4')"},` +
					`{"description":"Look up an indicator against an explicit reputation adapter with an API key, keeping only the malicious flag, score, and categories.",` +
					`"sql":"SELECT malicious, score, categories FROM threatintel.main.reputation('evil.example.com', base_url := 'https://my-reputation-adapter.internal/reputation', api_key := 'YOUR_KEY')"}` +
					`]`,
				// VGI509: guaranteed-runnable executable examples (offline-safe).
				"vgi.executable_examples": threatworker.ExecutableExamples,
			},
		}),
	)
	threatworker.Register(w)

	if *httpMode {
		if err := w.RunHttp("127.0.0.1:0"); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *unixPath != "" {
		// AF_UNIX launcher transport: serve on the given socket path. The SDK
		// prints "UNIX:<path>" once listening; idleTimeout=0 disables the
		// self-shutdown timer (the launcher/CI owns the process lifecycle).
		if err := w.RunUnix(*unixPath, 0); err != nil {
			log.Fatal(err)
		}
		return
	}
	w.RunStdio()
}

// filterKnownFlags drops argv tokens for flags this binary doesn't define, so
// launcher-injected differentiation flags don't abort flag parsing. Flags named
// in valueFlags consume the following token as their value.
func filterKnownFlags(args []string, valueFlags map[string]bool) []string {
	defined := map[string]bool{}
	flag.CommandLine.VisitAll(func(f *flag.Flag) { defined[f.Name] = true })
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		hasInlineValue := strings.ContainsRune(name, '=')
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if !defined[name] {
			continue
		}
		out = append(out, a)
		if valueFlags[name] && !hasInlineValue && i+1 < len(args) {
			i++
			out = append(out, args[i])
		}
	}
	return out
}
