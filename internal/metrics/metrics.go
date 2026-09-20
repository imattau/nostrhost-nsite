// Package metrics provides the gateway's Prometheus instrumentation. The
// counters, histograms and registry are backed by the official client_golang
// collectors and served through promhttp.HandlerFor on the loopback /internal
// endpoint. Metric names, labels, buckets and the text exposition (version
// 0.0.4) are preserved from the previous dependency-free registry so scrape
// consumers see an identical surface.
package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Counter is a monotonic counter, optionally labelled. A family is created by
// Registry.Counter; With(...) returns a scoped view for one label set. The
// label set is validated once at With-time (wrong arity panics), so a
// mismatched label set cannot silently mis-record.
type Counter struct {
	name      string
	labelKeys []string

	mu  *sync.Mutex
	vec *prometheus.CounterVec
	cur prometheus.Counter // scoped view (nil on the family handle)
}

func (c *Counter) With(labelValues ...string) *Counter {
	if len(labelValues) != len(c.labelKeys) {
		panic(fmt.Sprintf("counter %s: got %d label values, want %d", c.name, len(labelValues), len(c.labelKeys)))
	}
	labels := make(prometheus.Labels, len(c.labelKeys))
	for i, k := range c.labelKeys {
		labels[k] = labelValues[i]
	}
	return &Counter{name: c.name, labelKeys: c.labelKeys, mu: c.mu, vec: c.vec, cur: c.vec.With(labels)}
}

func (c *Counter) Add(n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		// Unlabelled family: resolve the single child once, then add.
		if len(c.labelKeys) != 0 {
			panic(fmt.Sprintf("counter %s: Add called on a labelled family; use With() first", c.name))
		}
		c.cur = c.vec.With(prometheus.Labels{})
	}
	c.cur.Add(float64(n))
}

func (c *Counter) Inc() { c.Add(1) }

// Histogram is a fixed-bucket histogram over an observation distribution.
type Histogram struct {
	name      string
	labelKeys []string

	mu  *sync.Mutex
	vec *prometheus.HistogramVec
	cur prometheus.Observer // scoped view (nil on the family handle)
}

func (h *Histogram) With(labelValues ...string) *Histogram {
	if len(labelValues) != len(h.labelKeys) {
		panic(fmt.Sprintf("histogram %s: got %d label values, want %d", h.name, len(labelValues), len(h.labelKeys)))
	}
	labels := make(prometheus.Labels, len(h.labelKeys))
	for i, k := range h.labelKeys {
		labels[k] = labelValues[i]
	}
	return &Histogram{name: h.name, labelKeys: h.labelKeys, mu: h.mu, vec: h.vec, cur: h.vec.With(labels)}
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == nil {
		if len(h.labelKeys) != 0 {
			panic(fmt.Sprintf("histogram %s: Observe called on a labelled family; use With() first", h.name))
		}
		h.cur = h.vec.With(prometheus.Labels{})
	}
	h.cur.Observe(v)
}

// Registry holds all metric families on a private client_golang registry.
type Registry struct {
	mu  sync.Mutex
	reg *prometheus.Registry
	cs  map[string]*Counter
	hs  map[string]*Histogram
}

func New() *Registry {
	return &Registry{reg: prometheus.NewRegistry(), cs: map[string]*Counter{}, hs: map[string]*Histogram{}}
}

func (r *Registry) Counter(name, help string, labelKeys ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cs[name]; ok {
		return c
	}
	vec := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labelKeys)
	r.reg.MustRegister(vec)
	if len(labelKeys) == 0 {
		// Materialize the single unlabelled child so the family's HELP/TYPE
		// lines are present in the exposition even before the first Inc.
		vec.With(prometheus.Labels{})
	}
	c := &Counter{name: name, labelKeys: append([]string(nil), labelKeys...), mu: &sync.Mutex{}, vec: vec}
	r.cs[name] = c
	return c
}

func (r *Registry) Histogram(name, help string, buckets []float64, labelKeys ...string) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.hs[name]; ok {
		return h
	}
	vec := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help, Buckets: append([]float64(nil), buckets...)}, labelKeys)
	r.reg.MustRegister(vec)
	if len(labelKeys) == 0 {
		vec.With(prometheus.Labels{})
	}
	h := &Histogram{name: name, labelKeys: append([]string(nil), labelKeys...), mu: &sync.Mutex{}, vec: vec}
	r.hs[name] = h
	return h
}

// Handler returns the promhttp handler serving this registry in Prometheus
// text exposition format (version 0.0.4).
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Render returns the current exposition as a string (promhttp handler output).
func (r *Registry) Render() string {
	h := r.Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.ServeHTTP(rec, req)
	return rec.Body.String()
}