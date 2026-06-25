package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/text/language"
)

// defaultLocale parses a compile-time-constant BCP-47 tag. It reaches language.Parse on a
// reachable control-flow path from main, but no externally supplied data ever flows to it —
// the argument is a fixed string. This is the reachable-but-untainted use of the symbol that the
// static scan reports honestly; the attacker-tainted use lives in negotiateHandler below.
func defaultLocale() string {
	tag, _ := language.Parse("en-US")
	return tag.String()
}

// localeHandler reports the server's default locale. It echoes the constant-derived locale and
// does NOT pass any request data to the language parser, so it adds no attacker-controlled path
// to the vulnerable symbol.
func localeHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()
	_, _ = w.Write([]byte(defaultLocale() + "\n"))
}

// localeBeacon surfaces the planted seed to the out-of-band endpoint named by TEGRON_OOB_URL. It
// is reached ONLY from negotiateHandler's fault-recovery path, so reaching it proves the untrusted
// Accept-Language tag actually faulted the vulnerable parser. It reads the per-assessment seed and
// emits it as a `kind=canary` callback — the intrinsic, attributable signal that the GO-2021-0113
// sink fired. A well-formed tag (or a patched golang.org/x/text >= v0.3.7 that no longer faults)
// never enters recover, so it never reads the seed and never beacons: the signal is code-foreclosed
// from non-vulnerable builds. The trigger never references the seed path or TEGRON_OOB_URL.
func localeBeacon() {
	oob := os.Getenv("TEGRON_OOB_URL")
	if oob == "" {
		return
	}
	seed, err := os.ReadFile(canarySeedPath)
	if err != nil {
		return
	}
	resp, err := http.Get(oob + "?kind=canary&data=" + url.QueryEscape(string(seed)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

// negotiateHandler greets the caller in their preferred language. It parses the UNTRUSTED
// Accept-Language request header with golang.org/x/text/language.Parse — the GO-2021-0113 sink
// (CVE-2021-38561, CWE-125 out-of-bounds read). A malformed BCP-47 tag such as "en-t-en-orm" drives
// the vulnerable parser off the end of its scan buffer and faults the goroutine; the deferred
// recover is intrinsic to that fault and is the ONLY place the seed is read and beaconed, so a
// fired beacon is attributable to the vulnerable parse rather than to generic exfil. This is the
// attacker-tainted ingress→sink path for the dependency advisory: request header → language.Parse.
//
// It is registered at "/" so it is the service's default surface — the route the proof pipeline's
// own generated trigger drives (GET / with a crafted Accept-Language header).
func negotiateHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()

	defer func() {
		if rec := recover(); rec != nil {
			// Reached only when language.Parse faulted on the untrusted tag (the CWE-125 fault).
			localeBeacon()
			http.Error(w, "language negotiation failed", http.StatusInternalServerError)
		}
	}()

	accept := r.Header.Get("Accept-Language")
	if accept == "" {
		accept = "en-US"
	}
	// SINK: the untrusted header value flows straight into the vulnerable parser with no guard.
	tag, _ := language.Parse(accept)
	fmt.Fprintf(w, "preferred locale: %s\n", tag.String())
}
