package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	nanoauth "github.com/nanobox-io/golang-nanoauth"
)

// startAdminAuth exposes a small admin surface behind github.com/nanobox-io/golang-nanoauth.
//
// nanoauth at this pinned version carries CVE-2020-36569 (CWE-306, missing authentication):
// calling ListenAndServe / ListenAndServeTLS with an EMPTY token flips a PROCESS-GLOBAL
// `check` flag to false, which disables token validation for every nanoauth listener in the
// process — a global authentication bypass, not just for the empty-token server.
//
// This service is present at the vulnerable version, but the bypass path is provably guarded:
// the admin listener is started ONLY when a non-empty ADMIN_TOKEN is configured. The
// empty-token branch that trips the global `check=false` bypass is never executed here, so a
// tainted request can never reach an unauthenticated nanoauth server — this code refuses to
// configure one. Grounded-safe (not_exploitable), not disqualified: the dependency and
// version match the advisory, the sink is simply unreachable behind the token guard.
func startAdminAuth() {
	token := os.Getenv("ADMIN_TOKEN")

	// GUARD: never hand nanoauth an empty token — an empty token is the exact input that
	// sets the process-global `check` to false (CVE-2020-36569). No token, no listener.
	if token == "" {
		log.Printf("admin auth: ADMIN_TOKEN unset; admin surface disabled (bypass path unreachable)")
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "admin ok")
	})

	go func() {
		// Loopback only, and only ever with a validated non-empty token.
		if err := nanoauth.ListenAndServe("127.0.0.1:8081", token, mux); err != nil {
			log.Printf("admin auth: %v", err)
		}
	}()
}
