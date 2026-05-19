package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Business-domain Prometheus metrics for the vault service. These complement the
// transport-level HTTP metrics defined in middleware.go.
var (
	anonymizeOpsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_anonymize_ops_total",
		Help: "Total anonymize operations by category and outcome.",
	}, []string{"category", "outcome"})

	deanonymizeOpsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_deanonymize_ops_total",
		Help: "Total deanonymize operations by category and outcome.",
	}, []string{"category", "outcome"})

	fieldsAnonymizedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_fields_anonymized_total",
		Help: "Total PII fields anonymized by strategy.",
	}, []string{"strategy"})

	breakGlassRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_break_glass_requests_total",
		Help: "Total break-glass requests by outcome.",
	}, []string{"outcome"})

	activeBreakGlassSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vault_active_break_glass_sessions",
		Help: "Current number of active break-glass sessions.",
	})
)
