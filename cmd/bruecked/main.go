package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bruecke/internal/bruecke"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	cfg, err := bruecke.LoadConfig()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	seedSettings := bruecke.SeedVPNSettings(cfg)
	settings, err := bruecke.OpenSettingsStore(cfg.SettingsPath, seedSettings)
	if err != nil {
		logger.Fatalf("settings: %v", err)
	}
	seedSettings = settings.Get()
	network, serverIP, ipv6Network, ipv6ServerIP, err := seedSettings.Pools()
	if err != nil {
		logger.Fatalf("settings pool: %v", err)
	}
	store, err := bruecke.OpenStore(cfg.DatabasePath, network, serverIP, ipv6Network, ipv6ServerIP)
	if err != nil {
		logger.Fatalf("store: %v", err)
	}
	roots, err := bruecke.OpenRootStore(cfg.RootStorePath, cfg.DomainCAFiles, seedSettings)
	if err != nil {
		logger.Fatalf("domain store: %v", err)
	}

	wg := bruecke.NewScriptWireGuard(cfg, logger)
	if cfg.ApplyWireGuard {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		interfaceSettings, err := bruecke.DomainInterfaceSettings(roots.Domains(), seedSettings)
		if err != nil {
			cancel()
			logger.Fatalf("wireguard domain settings: %v", err)
		}
		if err := wg.Configure(ctx, interfaceSettings); err != nil {
			cancel()
			logger.Fatalf("wireguard configure: %v", err)
		}
		if err := wg.Sync(ctx, store.Clients()); err != nil {
			cancel()
			logger.Fatalf("wireguard sync: %v", err)
		}
		cancel()
	}

	remoteSubnets, err := bruecke.OpenRemoteSubnetStore(cfg.RemoteSubnetStorePath)
	if err != nil {
		logger.Fatalf("remote subnet store: %v", err)
	}
	remoteRuntime := bruecke.NewRemoteSubnetRuntime(cfg, logger)
	if cfg.ApplyRemoteSubnets {
		ctx, cancel := bruecke.RemoteRuntimeSyncContext()
		if err := remoteRuntime.Sync(ctx, remoteSubnets.Specs(), store.Clients()); err != nil {
			cancel()
			logger.Fatalf("remote subnet sync: %v", err)
		}
		cancel()
	}

	app := bruecke.NewServer(cfg, bruecke.ServerDependencies{
		Clients:       store,
		WireGuard:     wg,
		Roots:         roots,
		Settings:      settings,
		RemoteSubnets: remoteSubnets,
		RemoteRuntime: remoteRuntime,
		Logger:        logger,
	})
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	var acmeHTTPServer *http.Server
	if cfg.TLSTerminate {
		if err := os.MkdirAll(cfg.TLSCacheDir, 0o700); err != nil {
			logger.Fatalf("tls cache dir: %v", err)
		}
		logger.Printf("bruecke ACME hostname %s", cfg.TLSHostname)
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.TLSCacheDir),
			HostPolicy: autocert.HostWhitelist(cfg.TLSHostname),
		}
		tlsConfig := manager.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS12
		getCertificate := tlsConfig.GetCertificate
		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				copy := *hello
				copy.ServerName = cfg.TLSHostname
				hello = &copy
			}
			return getCertificate(hello)
		}
		httpServer.TLSConfig = tlsConfig
		acmeHTTPServer = &http.Server{
			Addr: cfg.ACMEHTTPAddr,
			Handler: manager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			})),
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		remoteShutdownCtx, remoteCancel := context.WithTimeout(context.Background(), 10*time.Second)
		remoteRuntime.StopAll(remoteShutdownCtx)
		remoteCancel()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		if acmeHTTPServer != nil {
			_ = acmeHTTPServer.Shutdown(shutdownCtx)
		}
	}()
	if acmeHTTPServer != nil {
		go func() {
			logger.Printf("bruecke ACME HTTP listening on %s", cfg.ACMEHTTPAddr)
			err := acmeHTTPServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("acme http server: %v", err)
			}
		}()
	}

	logger.Printf("bruecke listening on %s", cfg.HTTPAddr)
	if cfg.TLSTerminate {
		listener, err := tls.Listen("tcp", cfg.HTTPAddr, httpServer.TLSConfig)
		if err != nil {
			logger.Fatalf("tls listen: %v", err)
		}
		defer listener.Close()
		err = httpServer.Serve(listener)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("server: %v", err)
	}
}
