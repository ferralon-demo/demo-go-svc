package main

import (
	"fmt"
	"io"
	"net/http"
)

// fetchHandler implements the URL-preview endpoint. It forwards a caller-supplied target
// directly to an outbound HTTP request with no allowlist, so a request can drive the server
// to reach an internal or unintended host. The attacker-controlled `target` query parameter
// flows straight into http.Get — the server-side request forgery sink (CWE-918).
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	// SSRF sink: an unguarded outbound request to an attacker-influenced URL.
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	fmt.Fprintf(w, "fetched %s -> %s\n", target, resp.Status)
}
