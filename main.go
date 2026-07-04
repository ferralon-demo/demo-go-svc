// Command demo-go-svc is a small, genuinely runnable service used as a dependency-and-
// reachability scan demonstration fixture. It is deliberately curated so a single scan emits
// the honest verdict spread across several real dependency advisories:
//
//   - a reachable authorization-bypass candidate — golang.org/x/crypto/ssh's
//     PublicKeyCallback wired the vulnerable "last-key-wins" way (CVE-2024-45337), reachable
//     from the service's SSH-accepting entry point (the hero; see ssh.go);
//   - a present-but-guarded authentication bypass — github.com/nanobox-io/golang-nanoauth
//     (CVE-2020-36569), whose global-bypass path is foreclosed behind a token guard
//     (not_exploitable; see auth.go);
//   - a version-disqualified input-validation advisory — golang.org/x/net/idna
//     (CVE-2026-39821), imported and reachable but pinned past the fixed range
//     (disqualified; see normalize.go);
//
// plus the attacker-tainted SSRF and DoS ingress→sink candidates the HTTP service exposes.
// It is real code: `go build ./...` succeeds, and the binary serves HTTP on :8080 and SSH on
// :2022.
//
// HTTP surface:
//
//	GET /                   usage banner
//	GET /healthz            liveness probe
//	GET /preview?target=…   fetch a remote URL and report its status (the SSRF surface)
//	GET /expand?count=…     allocate a working buffer of the requested size (the DoS surface)
//	GET /normalize?host=…   IDNA-normalise a host to ASCII/Punycode (the x/net/idna use)
//
// SSH surface (the hero):
//
//	:2022                   public-key SSH with the CVE-2024-45337 callback misuse
//
// Naming note: nothing user-visible here references the scanner or its brand; this is
// internal fixture code whose externally observable behaviour is an ordinary service.
package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

// requestsTotal is registered with the default Prometheus registry but is never exposed
// through a promhttp handler. The vulnerable promhttp scrape symbol is therefore present in
// the dependency graph yet unreachable from any call path in this binary.
var requestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "demo_requests_total",
	Help: "Total number of requests handled by the service.",
})

func init() {
	prometheus.MustRegister(requestsTotal)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()
	_, _ = w.Write([]byte("ok\n"))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()
	_, _ = w.Write([]byte("demo-go-svc — HTTP on :8080, SSH on :2022\n"))
}

func main() {
	// Start the SSH entry point (the CVE-2024-45337 hero surface) alongside HTTP. A live fire
	// drives this listener; a static scan reaches the vulnerable PublicKeyCallback from here.
	go serveSSH("127.0.0.1:2022")

	// Start the nanoauth-protected admin surface — guarded off unless a non-empty ADMIN_TOKEN
	// is configured, so the CVE-2020-36569 empty-token global bypass is never reachable.
	startAdminAuth()

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/preview", fetchHandler)
	mux.HandleFunc("/expand", expandHandler)
	mux.HandleFunc("/normalize", normalizeHandler)

	addr := "127.0.0.1:8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
