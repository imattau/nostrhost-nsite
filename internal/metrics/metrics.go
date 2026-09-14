// Package metrics is a tiny dependency-free counters/histograms registry for
// the gateway, rendered as Prometheus text format on the loopback /internal
// endpoint. The exposition is deliberate: no third-party client library, just
// monotonic counters and fixed buckets, matching the plan's "counters/
// histograms (requests, cache hits, fetch failures by class, bytes served)".
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Counter is a monotonic counter, optionally labelled. A family is created by
// Registry.Counter; With(...) returns a scoped view for one label set. The
// label set is validated once at With-time (wrong arity panics), so a
// mismatched label set cannot silently mis-record.
type Counter struct {
	name, help string
	labelKeys  []string

	mu     *sync.Mutex
	values map[string]int64 // label-set key -> value
	fixed  string           // "" for the family, or the scoped label-set key
}

func (c *Counter) key(labelValues []string) string {
	return strings.Join(labelValues, "\x00")
}

// With returns a scoped view of this counter for the given label values.
func (c *Counter) With(labelValues ...string) *Counter {
	if len(labelValues) != len(c.labelKeys) {
		panic(fmt.Sprintf("counter %s: got %d label values, want %d", c.name, len(labelValues), len(c.labelKeys)))
	}
	return &Counter{name: c.name, help: c.help, labelKeys: c.labelKeys, values: c.values, mu: c.mu, fixed: c.key(labelValues)}
}

func (c *Counter) Add(n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[c.fixed] += n
}

func (c *Counter) Inc() { c.Add(1) }

// Histogram is a fixed-bucket histogram over an observation distribution.
type Histogram struct {
	name, help string
	labelKeys  []string
	buckets    []float64 // ascending upper bounds

	mu     *sync.Mutex
	counts map[string][]int64 // label-set key -> per-bucket counts
	sums   map[string]float64
	obs    map[string]int64
	fixed  string
}

func (h *Histogram) With(labelValues ...string) *Histogram {
	if len(labelValues) != len(h.labelKeys) {
		panic(fmt.Sprintf("histogram %s: got %d label values, want %d", h.name, len(labelValues), len(h.labelKeys)))
	}
	return &Histogram{
		name: h.name, help: h.help, labelKeys: h.labelKeys, buckets: h.buckets,
		mu: h.mu, counts: h.counts, sums: h.sums, obs: h.obs, fixed: strings.Join(labelValues, "\x00"),
	}
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	counts := h.counts[h.fixed]
	if counts == nil {
		counts = make([]int64, len(h.buckets))
		h.counts[h.fixed] = counts
	}
	idx := 0
	for i, b := range h.buckets {
		if v <= b {
			idx = i
			break
		}
		idx = i + 1
	}
	// A value beyond the last bucket counts as overflow (no +Inf bucket by
	// default; the +Inf line is derived as the total count).
	for i := idx; i < len(counts); i++ {
		counts[i]++
	}
	h.sums[h.fixed] += v
	h.obs[h.fixed]++
}

// Registry holds all metric families.
type Registry struct {
	mu sync.Mutex
	cs map[string]*Counter
	hs map[string]*Histogram
}

func New() *Registry {
	return &Registry{cs: map[string]*Counter{}, hs: map[string]*Histogram{}}
}

func (r *Registry) Counter(name, help string, labelKeys ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cs[name]; ok {
		return c
	}
	c := &Counter{name: name, help: help, labelKeys: labelKeys, values: map[string]int64{}, mu: &sync.Mutex{}}
	r.cs[name] = c
	return c
}

func (r *Registry) Histogram(name, help string, buckets []float64, labelKeys ...string) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.hs[name]; ok {
		return h
	}
	h := &Histogram{
		name: name, help: help, labelKeys: labelKeys, buckets: append([]float64(nil), buckets...),
		counts: map[string][]int64{}, sums: map[string]float64{}, obs: map[string]int64{}, mu: &sync.Mutex{},
	}
	r.hs[name] = h
	return h
}

// Render emits the registry in Prometheus text exposition format.
func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	cNames := make([]string, 0, len(r.cs))
	for n := range r.cs {
		cNames = append(cNames, n)
	}
	sort.Strings(cNames)
	for _, n := range cNames {
		c := r.cs[n]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", n, c.help, n)
		keys := make([]string, 0, len(c.values))
		for k := range c.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s%s %d\n", n, labelSuffix(c.labelKeys, k), c.values[k])
		}
	}
	hNames := make([]string, 0, len(r.hs))
	for n := range r.hs {
		hNames = append(hNames, n)
	}
	sort.Strings(hNames)
	for _, n := range hNames {
		h := r.hs[n]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", n, h.help, n)
		keys := make([]string, 0, len(h.counts))
		for k := range h.counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			counts := h.counts[k]
			for i, upper := range h.buckets {
				fmt.Fprintf(&b, "%s_bucket%s %d\n", n, labelSuffixWith(h.labelKeys, k, "le", fmt.Sprintf("%g", upper)), counts[i])
			}
			total := h.obs[k]
			fmt.Fprintf(&b, "%s_bucket%s %d\n", n, labelSuffixWith(h.labelKeys, k, "le", "+Inf"), total)
			fmt.Fprintf(&b, "%s_sum%s %g\n", n, labelSuffix(h.labelKeys, k), h.sums[k])
			fmt.Fprintf(&b, "%s_count%s %d\n", n, labelSuffix(h.labelKeys, k), total)
		}
	}
	return b.String()
}

// labelSuffix builds the `{k="v",...}` suffix for a metric line.
func labelSuffix(labelKeys []string, key string) string {
	return labelSuffixWith(labelKeys, key, "", "")
}

func labelSuffixWith(labelKeys []string, key, extraKey, extraVal string) string {
	values := strings.Split(key, "\x00")
	if len(values) != len(labelKeys) {
		values = nil
	}
	var b strings.Builder
	wrote := false
	for i, k := range labelKeys {
		if wrote {
			b.WriteByte(',')
		}
		wrote = true
		fmt.Fprintf(&b, "%s=\"%s\"", k, escape(values[i]))
	}
	if extraKey != "" {
		if wrote {
			b.WriteByte(',')
		}
		wrote = true
		fmt.Fprintf(&b, "%s=\"%s\"", extraKey, escape(extraVal))
	}
	if !wrote {
		return "" // no labels at all (unlabelled metric line)
	}
	b.WriteByte('}')
	return "{" + b.String()
}

func escape(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
