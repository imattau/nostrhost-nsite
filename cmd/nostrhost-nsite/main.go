// nostrhost-nsite is the optional NIP-5A static-site gateway (Phase 1,
// docs/NSITES-IMPLEMENTATION-PLAN.md). It is disabled by default; enabling it
// registers a dedicated gateway domain in Caddy and serves allowlisted sites.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/blossomsrv"
	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/npk"
	"github.com/imattau/nostrhost-nsite/internal/resolve"
	"github.com/imattau/nostrhost-nsite/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/nostrhost/nsite.toml", "path to nsite.toml")
	checkOnly := flag.Bool("check-config", false, "load and validate the config, then exit (used by the config projector before atomic replace)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	if *checkOnly {
		// Native config checker for WP7: the Python projector shells to this
		// before writing nsite.toml, so a render that the gateway would refuse
		// is never installed. Exits 0 only when Load+Validate succeed.
		log.Info("config ok", "mode", cfg.Mode, "domain", cfg.Domain)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, log)
	applyBackends(srv, cfg, log)
	bs := startBlossom(ctx, cfg, log)

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
				bs = reloadBlossom(ctx, bs, reloaded, log)
			}
		}
	}()

	log.Info("nostrhost-nsite starting", "config", *configPath, "mode", cfg.Mode, "domain", cfg.Domain)
	if err := srv.Start(ctx); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
	stopBlossom(ctx, bs)
	log.Info("nostrhost-nsite stopped")
}

// blossomServer owns the optional local Blossom server lifecycle (D4).
type blossomServer struct {
	http   *http.Server
	listen net.Listener
}

// startBlossom launches the local Blossom server when [blossom.local] is
// enabled. It returns nil when the component is disabled. The listener is
// bound to the configured loopback address only (validated by config).
func startBlossom(ctx context.Context, cfg *config.Config, log *slog.Logger) *blossomServer {
	if !cfg.Blossom.Local.Enabled {
		return nil
	}
	ln, err := net.Listen("tcp", cfg.Blossom.Local.Listen)
	if err != nil {
		log.Error("blossom listen", "addr", cfg.Blossom.Local.Listen, "err", err)
		os.Exit(1)
	}
	bs, err := blossomsrv.New(blossomsrv.Options{
		Dir:           cfg.Blossom.Local.DataDir,
		QuotaBytes:    cfg.Blossom.Local.QuotaBytes,
		MaxBlobBytes:  cfg.Blossom.Local.MaxBlobBytes,
		Retention:     time.Duration(cfg.Blossom.Local.RetentionDays) * 24 * time.Hour,
		AllowPubkeys:  cfg.Blossom.Local.AllowPubkeys,
		Log:           log,
	})
	if err != nil {
		log.Error("blossom store", "err", err)
		os.Exit(1)
	}
	_ = bs.Sweep() // apply retention on start, best effort
	httpSrv := &http.Server{
		Handler: bs.Handler(),
		// The store is content-addressed and bounded by the quota/max-blob
		// caps; give uploads a generous but finite write deadline.
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Error("blossom serve", "addr", cfg.Blossom.Local.Listen, "err", err)
		}
	}()
	log.Info("local Blossom server listening", "addr", cfg.Blossom.Local.Listen, "quota", cfg.Blossom.Local.QuotaBytes, "retention_days", cfg.Blossom.Local.RetentionDays)
	return &blossomServer{http: httpSrv, listen: ln}
}

// reloadBlossom reconciles the local Blossom server against a reloaded
// config: enabled->disabled stops it, disabled->enabled starts it, and an
// unchanged enabled state is left running (SIGHUP does not restart the store).
func reloadBlossom(ctx context.Context, cur *blossomServer, cfg *config.Config, log *slog.Logger) *blossomServer {
	if cfg.Blossom.Local.Enabled {
		if cur == nil {
			return startBlossom(ctx, cfg, log)
		}
		return cur
	}
	if cur != nil {
		stopBlossom(ctx, cur)
	}
	return nil
}

// stopBlossom shuts the local Blossom server down.
func stopBlossom(ctx context.Context, bs *blossomServer) {
	if bs == nil || bs.http == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = bs.http.Shutdown(shutdownCtx)
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
	var npkBundles *npk.BundleStore
	if cfg.Npk.Enabled {
		npkBundles, err = npk.NewBundleStore(cfg.Npk.CachePath)
		if err != nil {
			log.Error("npk bundle cache", "err", err)
			os.Exit(1)
		}
		log.Info("npk bundle store ready", "cache", cfg.Npk.CachePath)
	}
	// Optional local npack catalogue: `npack refresh` output that backs
	// release resolution without a relay round trip. A missing file is not an
	// error (falls back to relays); a parse failure logs and also falls back.
	var catalogue *npk.Catalogue
	if cfg.Npk.CataloguePath != "" {
		catalogue, err = npk.LoadCatalogue(cfg.Npk.CataloguePath)
		if err != nil {
			log.Warn("npk catalogue unavailable; release resolution falls back to relays", "path", cfg.Npk.CataloguePath, "err", err)
		} else if catalogue != nil {
			log.Info("npk catalogue loaded", "path", cfg.Npk.CataloguePath, "created_at", catalogue.CreatedAt)
		}
	}
	srv.Configure(server.Backends{
		Resolver: resolve.New(relays, mcache, nil, cfg.Limits.MaxPathsPerManifest, catalogue),
		Fetcher: blossom.New(blossom.Options{
			AllowHTTP: cfg.Blossom.AllowHTTP,
			AllowLoopback: os.Getenv("NSITE_ALLOW_LOOPBACK_RELAYS") == "1", // testbed only
			// D4: when the local Blossom server is enabled, grant the fetch
			// boundary an explicit allowance for that exact loopback address so
			// the gateway can resolve blobs from it. The allowance is
			// address-scoped (host:port), never a blanket loopback open.
			AllowLoopbackAddrs: localBlossomAddrs(cfg),
			MaxBytes:           int64(cfg.Limits.MaxBlobBytes),
			Timeout:            time.Duration(cfg.Limits.FetchTimeoutSeconds) * time.Second,
			MaxRedirects:       cfg.Limits.MaxRedirects,
		}),
		Blobs: blobs,
		Npk:   npkBundles,
	})
	log.Info("resolution stack ready", "relays", len(relays), "cache", cfg.CachePath)
}

// localBlossomAddrs returns the [blossom.local] listener as a host:port
// fetch-boundary allowance when the local server is enabled, else nil.
func localBlossomAddrs(cfg *config.Config) []string {
	if !cfg.Blossom.Local.Enabled {
		return nil
	}
	return []string{cfg.Blossom.Local.Listen}
}
