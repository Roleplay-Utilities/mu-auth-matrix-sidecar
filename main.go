package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// Server holds everything the HTTP handlers need: configuration, a shared HTTP client for
// talking to MU Auth and Zendrite, the cookie sealer, caches, and a logger. Nothing here is
// per-request state; a Server is created once and is safe for concurrent use. The only mutable
// state (the discovery/JWKS/provisioning caches) is purely an optimisation: losing it on restart,
// or running several independent instances without sharing it, changes nothing about
// correctness, only how often upstream calls are made.
type Server struct {
	cfg    *Config
	http   *http.Client
	sealer *sealer
	log    *logrus.Logger

	discovery   discoveryCache
	jwks        jwksCache
	provisioned provisionCache
}

func NewServer(cfg *Config, log *logrus.Logger) (*Server, error) {
	sl, err := newSealer(cfg.CookieSecret)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg,
		http: &http.Client{
			Timeout: 15 * time.Second,
			// Never follow redirects automatically: credentials must not be silently replayed to
			// wherever a redirect points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sealer:      sl,
		log:         log,
		provisioned: provisionCache{entries: make(map[string]time.Time)},
	}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /oauth2/jwks", s.handleJWKS)
	mux.HandleFunc("GET /oauth2/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /oauth2/token", s.handleToken)
	mux.HandleFunc("POST /oauth2/introspect", s.handleIntrospect)

	if s.cfg.DashboardEnabled() {
		mux.HandleFunc("GET /account", s.handleAccountPage)
		mux.HandleFunc("GET /account/callback", s.handleAccountCallback)
		mux.HandleFunc("POST /account/logout", s.handleAccountLogout)
		mux.HandleFunc("GET /api/devices", s.handleListDevices)
		mux.HandleFunc("DELETE /api/devices/{device_id}", s.handleDeleteDevice)
	}

	// The 12 MAS admin/provisioning actions, each on its own exact path and method — never a
	// wildcard — so nothing outside this explicit set is ever reachable under /_synapse/mas/.
	mux.HandleFunc("GET /_synapse/mas/query_user", s.handleManage("query_user", http.MethodGet))
	mux.HandleFunc("GET /_synapse/mas/is_localpart_available", s.handleManage("is_localpart_available", http.MethodGet))
	mux.HandleFunc("POST /_synapse/mas/provision_user", s.handleManage("provision_user", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/upsert_device", s.handleManage("upsert_device", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/update_device_display_name", s.handleManage("update_device_display_name", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/delete_device", s.handleManage("delete_device", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/sync_devices", s.handleManage("sync_devices", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/delete_user", s.handleManage("delete_user", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/reactivate_user", s.handleManage("reactivate_user", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/set_displayname", s.handleManage("set_displayname", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/unset_displayname", s.handleManage("unset_displayname", http.MethodPost))
	mux.HandleFunc("POST /_synapse/mas/allow_cross_signing_reset", s.handleManage("allow_cross_signing_reset", http.MethodPost))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	return s.logMiddleware(s.corsMiddleware(mux))
}

// corsMiddleware allows cross-origin calls only to the OAuth endpoints (native and browser-based
// Matrix clients call these from their own origin). /account and /api are same-origin only; they
// are read by the dashboard page itself via cookies, which browsers never send cross-origin
// without explicit opt-in, so no CORS headers are needed or added for them.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth2/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.WithFields(logrus.Fields{
			"method": r.Method, "path": r.URL.Path, "status": rec.status,
			"duration_ms": time.Since(start).Milliseconds(),
		}).Info("request")
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func main() {
	EnsureInstalledAndRegistered()
	exPath, err := getExecutablePath()
	if err == nil {
		envPath := filepath.Join(filepath.Dir(exPath), ".env")
		_ = godotenv.Load(envPath)
	} else {
		_ = godotenv.Load()
	}
	
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	s, err := NewServer(cfg, log)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodic update checker
	go func() {
		time.Sleep(10 * time.Second)
		CheckForUpdates()

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				CheckForUpdates()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Cache sweeper
	stopSweep := make(chan struct{})
	defer close(stopSweep)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.provisioned.sweep()
			case <-stopSweep:
				return
			}
		}
	}()

	addr := ":" + cfg.Port
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.WithFields(logrus.Fields{
		"listen":    addr,
		"mu_auth":   cfg.MUIssuer.String(),
		"zendrite":  cfg.ZendriteURL.String(),
		"dashboard": cfg.DashboardEnabled(),
	}).Info("mu-auth-matrix-sidecar starting")

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}