package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/idna"
)

// normalizeHandler converts an internationalized host name to its ASCII (Punycode) form with
// golang.org/x/net/idna. CVE-2026-39821 (CWE-20, input-validation privilege escalation)
// concerns idna label processing in golang.org/x/net BELOW its fixed range (< v0.55.0). This
// module pins golang.org/x/net to v0.32.0 (see go.mod), which is INSIDE that affected range,
// and the idna component is genuinely imported and reached from this endpoint — the
// attacker-controllable /normalize route flows into idna.ToASCII. The free scan therefore
// reports a reachable_candidate: a candidate for review, never a claim of exploitability.
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
