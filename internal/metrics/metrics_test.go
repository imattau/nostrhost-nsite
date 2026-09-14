package metrics

import (
	"strings"
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
