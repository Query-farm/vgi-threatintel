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
			"vgi.keywords": "threat intelligence, threat intel, indicators, ioc, ip, domain, url, " +
				"file hash, reputation, malicious, enrichment, classification, soc, threat hunting, " +
				"incident response, cyber, defensive security",
			"vgi.doc_llm": "Defensive threat-intelligence worker for cyber indicators (IoCs). " +
				"Offline scalars classify an indicator string as ipv4/ipv6/domain/url/md5/sha1/sha256 " +
				"(indicator_type) and flag private/reserved IPs that should not be looked up " +
				"(is_private_ip); the reputation table function enriches one indicator against a " +
				"threat-intel reputation source, returning at most one verdict row with a malicious " +
				"flag, score, categories, source, and last_seen. Use to triage and enrich IPs, " +
				"domains, URLs, and file hashes in SQL during SOC / threat-hunting work (AUTHORIZED use only).",
			"vgi.doc_md": "# threatintel\n\n" +
				"Enrich and classify cyber indicators (IPs, domains, URLs, file hashes) against a " +
				"threat-intel reputation source, exposed as DuckDB SQL functions. Defensive " +
				"SOC / threat-hunting tool for AUTHORIZED use.\n\n" +
				"Scalars: `indicator_type`, `is_private_ip`. Table: `reputation`.",
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
				"vgi.keywords": "threat intel, indicator, ioc, indicator_type, is_private_ip, " +
					"reputation, classify, enrich, ip, domain, url, file hash, malicious, soc, " +
					"threat hunting",
				// VGI123 classifying tags MUST use BARE keys (not vgi.-namespaced).
				"domain":   "security",
				"category": "threat-intelligence",
				"topic":    "indicator-enrichment",
				"vgi.source_url": "https://github.com/Query-farm/vgi-threatintel/blob/main/" +
					"internal/threatworker/functions.go",
				"vgi.doc_llm": "Threat-intel functions: classify an indicator's IoC type " +
					"(indicator_type), flag private/reserved IPs (is_private_ip), and enrich one " +
					"indicator against a reputation source (reputation table function).",
				"vgi.doc_md": "Threat-intel indicator classification and reputation-enrichment " +
					"functions over Apache Arrow.",
				// VGI506 representative example queries (a plain string; not executed).
				// Includes a backend-qualified reputation lookup, which the offline
				// linter run does not execute.
				"vgi.example_queries": "SELECT threatintel.main.indicator_type('8.8.8.8');\n" +
					"SELECT threatintel.main.is_private_ip('10.0.0.5');\n" +
					"SELECT * FROM threatintel.main.reputation('1.2.3.4');\n" +
					"SELECT malicious, score, categories FROM threatintel.main.reputation('evil.example.com', base_url := 'https://my-reputation-adapter.internal/reputation', api_key := 'YOUR_KEY');",
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
