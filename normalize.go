package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/idna"
)

// normalizeHandler converts an internationalized host name to its ASCII (Punycode) form with
// golang.org/x/net/idna. CVE-2026-39821 (CWE-20, input-validation privilege escalation)
// concerns idna label processing in golang.org/x/net BELOW its fixed range. This module pins
// golang.org/x/net to a release PAST that range (see go.mod), so the advisory is disqualified
// by version: the idna component is genuinely imported and reachable from this endpoint, but
// the resolved version is already patched, which is what puts it out of scope.
func normalizeHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()

	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "%s -> %s\n", host, ascii)
}
