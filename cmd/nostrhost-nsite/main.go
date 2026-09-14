// nostrhost-nsite is the optional NIP-5A static-site gateway (Phase 1,
// docs/NSITES-IMPLEMENTATION-PLAN.md). It is disabled by default; enabling it
// registers a dedicated gateway domain in Caddy and serves allowlisted sites.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/resolve"
	"github.com/imattau/nostrhost-nsite/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/nostrhost/nsite.toml", "path to nsite.toml")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, log)
	applyBackends(srv, cfg, log)

	// SIGHUP reloads the config, allowlist and resolution stack without
	// dropping connections.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				reloaded, err := config.Load(*configPath)
				if err != nil {
					log.Error("reload config", "err", err)
					continue
				}
				srv.Reload(reloaded)
				applyBackends(srv, reloaded, log)
			}
		}
	}()

	log.Info("nostrhost-nsite starting", "config", *configPath, "mode", cfg.Mode, "domain", cfg.Domain)
	if err := srv.Start(ctx); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
	log.Info("nostrhost-nsite stopped")
}

// applyBackends builds the Phase 1.3 resolution stack from config: manifest
// cache, resolver over the configured relays, SSRF-safe blossom fetcher and
// the content-addressed blob cache.
func applyBackends(srv *server.Server, cfg *config.Config, log *slog.Logger) {
	relays := append(append([]string{}, cfg.Relays.Lookup...), cfg.Relays.Extra...)
	mcache := cache.NewManifestCache(
		time.Duration(cfg.Relays.ManifestTTLSeconds)*time.Second,
		time.Duration(cfg.Relays.NegativeTTLSeconds)*time.Second,
	)
	blobs, err := cache.NewBlobStore(cfg.CachePath, cfg.Limits.CacheQuotaBytes)
	if err != nil {
		log.Error("blob cache", "err", err)
		os.Exit(1)
	}
	srv.Configure(server.Backends{
		Resolver: resolve.New(relays, mcache, nil, cfg.Limits.MaxPathsPerManifest),
		Fetcher: blossom.New(blossom.Options{
			AllowHTTP:     cfg.Blossom.AllowHTTP,
			AllowLoopback: os.Getenv("NSITE_ALLOW_LOOPBACK_RELAYS") == "1", // testbed only
			MaxBytes:      int64(cfg.Limits.MaxBlobBytes),
			Timeout:       time.Duration(cfg.Limits.FetchTimeoutSeconds) * time.Second,
			MaxRedirects:  cfg.Limits.MaxRedirects,
		}),
		Blobs: blobs,
	})
	log.Info("resolution stack ready", "relays", len(relays), "cache", cfg.CachePath)
}
