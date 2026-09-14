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

	"github.com/imattau/nostrhost-nsite/internal/config"
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

	// SIGHUP reloads the config and allowlist without dropping connections.
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
