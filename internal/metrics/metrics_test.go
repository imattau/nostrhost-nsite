package metrics

import (
	"strings"
	"sync"
	"testing"
)

func TestCounterLabels(t *testing.T) {
	r := New()
	c := r.Counter("nostrhost_nsite_requests_total", "requests", "class")
	c.With("apex").Inc()
	c.With("apex").Inc()
	c.With("site").Add(3)
	out := r.Render()
	if !strings.Contains(out, `nostrhost_nsite_requests_total{class="apex"} 2`) {
		t.Fatalf("missing apex counter:\n%s", out)
	}
	if !strings.Contains(out, `nostrhost_nsite_requests_total{class="site"} 3`) {
		t.Fatalf("missing site counter:\n%s", out)
	}
}

func TestCounterNoLabels(t *testing.T) {
	r := New()
	c := r.Counter("nostrhost_nsite_cache_hits_total", "cache hits")
	c.Add(7)
	out := r.Render()
	if !strings.Contains(out, "nostrhost_nsite_cache_hits_total 7") {
		t.Fatalf("missing unlabelled counter:\n%s", out)
	}
}

func TestHistogram(t *testing.T) {
	r := New()
	h := r.Histogram("nostrhost_nsite_bytes_served", "bytes served", []float64{10, 100, 1000})
	h.Observe(5)
	h.Observe(50)
	h.Observe(5000)
	out := r.Render()
	for _, want := range []string{
		`nostrhost_nsite_bytes_served_bucket{le="10"} 1`,
		`nostrhost_nsite_bytes_served_bucket{le="100"} 2`,
		`nostrhost_nsite_bytes_served_bucket{le="1000"} 2`,
		`nostrhost_nsite_bytes_served_bucket{le="+Inf"} 3`,
		"nostrhost_nsite_bytes_served_sum 5055",
		"nostrhost_nsite_bytes_served_count 3",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestLabelArityPanics(t *testing.T) {
	r := New()
	c := r.Counter("nostrhost_nsite_requests_total", "requests", "class")
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic on wrong label arity")
		}
	}()
	c.With("apex", "extra")
}

func TestGoldenExposition(t *testing.T) {
	// Deterministic golden output for the metric surface used by the gateway.
	r := New()
	r.Counter("nostrhost_nsite_cache_hits_total", "blob served from the on-disk cache")
	r.Counter("nostrhost_nsite_fetch_failures_total", "blob fetch failures by class", "class").With("network").Inc()
	r.Counter("nostrhost_nsite_requests_total", "public requests by class", "class").With("apex").Inc()
	r.Counter("nostrhost_nsite_requests_total", "public requests by class", "class").With("site").Inc()
	r.Histogram("nostrhost_nsite_bytes_served", "response body bytes served", []float64{1024, 16 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20}).Observe(2048)
	got := r.Render()
	for _, want := range []string{
		"# HELP nostrhost_nsite_cache_hits_total blob served from the on-disk cache",
		"# TYPE nostrhost_nsite_cache_hits_total counter",
		"nostrhost_nsite_cache_hits_total 0",
		`nostrhost_nsite_fetch_failures_total{class="network"} 1`,
		`nostrhost_nsite_requests_total{class="apex"} 1`,
		`nostrhost_nsite_requests_total{class="site"} 1`,
		`nostrhost_nsite_bytes_served_bucket{le="1024"} 0`,
		`nostrhost_nsite_bytes_served_bucket{le="16384"} 1`,
		`nostrhost_nsite_bytes_served_bucket{le="262144"} 1`,
		`nostrhost_nsite_bytes_served_bucket{le="+Inf"} 1`,
		"nostrhost_nsite_bytes_served_sum 2048",
		"nostrhost_nsite_bytes_served_count 1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in golden output:\n%s", want, got)
		}
	}
}

func TestConcurrentConsistency(t *testing.T) {
	r := New()
	c := r.Counter("nostrhost_nsite_requests_total", "requests", "class")
	h := r.Histogram("nostrhost_nsite_bytes_served", "bytes served", []float64{10, 100, 1000})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.With("apex").Inc()
				h.Observe(float64(j))
				_ = r.Render()
			}
		}()
	}
	wg.Wait()
	out := r.Render()
	if !strings.Contains(out, `nostrhost_nsite_requests_total{class="apex"} 1600`) {
		t.Fatalf("counter lost increments under concurrency:\n%s", out)
	}
	if !strings.Contains(out, "nostrhost_nsite_bytes_served_count 1600") {
		t.Fatalf("histogram lost observations under concurrency:\n%s", out)
	}
}