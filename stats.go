package main

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type SidecarMetrics struct {
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	oauthFlowsTotal     *prometheus.CounterVec
	deviceProvisionTotal *prometheus.CounterVec
}

func NewSidecarMetrics() *SidecarMetrics {
	m := &SidecarMetrics{
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mu_sidecar_http_requests_total",
				Help: "Total HTTP requests processed by the sidecar, labeled by status, method, and endpoint.",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "mu_sidecar_http_request_duration_seconds",
				Help:    "HTTP request latency distributions.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		oauthFlowsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mu_sidecar_oauth_flows_total",
				Help: "Track successful or failed OAuth lifecycle steps (authorize, token, introspect).",
			},
			[]string{"step", "status"},
		),
		deviceProvisionTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mu_sidecar_device_provisions_total",
				Help: "Count of devices registered/upserted to Zendrite with their display names.",
			},
			[]string{"status"},
		),
	}

	prometheus.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.oauthFlowsTotal,
		m.deviceProvisionTotal,
	)

	return m
}

// HTTP middleware to wrap your handlers and automatically record metrics
func (m *SidecarMetrics) InstrumentHandler(path string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Capture status code using a response writer wrapper
		rw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		
		next(rw, r)
		
		duration := time.Since(start).Seconds()
		statusStr := http.StatusText(rw.status)
		
		m.httpRequestsTotal.WithLabelValues(r.Method, path, statusStr).Inc()
		m.httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	}
}

// Helper writer to catch status codes
type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Expose standard Prometheus handler endpoint
func HandleMetrics() http.Handler {
	return promhttp.Handler()
}