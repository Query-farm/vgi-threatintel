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
	// Accept --http for HTTP transport; default is stdio. Unknown launcher
	// flags are tolerated (the VGI extension varies argv to key its worker
	// cache), so we filter to flags we actually define before parsing.
	httpMode := flag.Bool("http", false, "Run as an HTTP server instead of stdio")
	logFlags := vgi.RegisterLoggingFlags(flag.CommandLine)
	_ = flag.CommandLine.Parse(filterKnownFlags(os.Args[1:], map[string]bool{
		"log-level":  true,
		"log-format": true,
		"log-logger": true,
	}))
	if err := logFlags.Apply(); err != nil {
		log.Fatalf("logging flags: %v", err)
	}

	w := vgi.NewWorker(
		vgi.WithCatalogName(threatworker.CatalogName),
		vgi.WithCatalogComment("Enrich cyber indicators against threat-intel reputation sources; classify offline"),
		vgi.WithCatalogTags(map[string]string{
			"source": "vgi-threatintel",
		}),
	)
	threatworker.Register(w)

	if *httpMode {
		if err := w.RunHttp("127.0.0.1:0"); err != nil {
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
