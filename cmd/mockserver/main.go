// Copyright 2026 Query Farm LLC - https://query.farm

// Command mockserver runs a standalone HTTP server that serves canned,
// normalized threat-intel reputation JSON (from internal/mockrep). It is used by
// the haybarn SQL end-to-end tests: the Makefile starts it on a free port, reads
// the printed PORT line, and points the worker's reputation table function at it
// via the base_url option.
//
// Usage:
//
//	mockserver [--addr 127.0.0.1:0] [--api-key KEY]
//
// On startup it prints "PORT:<n>" (the bound TCP port) to stdout so a caller can
// discover the port even when binding to :0. If --api-key is set, every request
// must present a matching X-API-Key header.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Query-farm/vgi-threatintel/internal/mockrep"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "TCP address to listen on (host:port; port 0 = pick a free port)")
	apiKey := flag.String("api-key", "", "If set, require this value in the X-API-Key header")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("mockserver: listen %q: %v", *addr, err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	fmt.Printf("PORT:%d\n", port)
	_ = os.Stdout.Sync()

	srv := &http.Server{Handler: mockrep.Handler(*apiKey)}

	// Graceful shutdown on SIGINT/SIGTERM so the Makefile's `kill` is clean.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
		log.Fatalf("mockserver: serve: %v", err)
	}
}
