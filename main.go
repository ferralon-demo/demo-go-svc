// Command demo-go-svc is a small, genuinely runnable HTTP service used as a static-scanner
// demonstration fixture. It is deliberately curated so a single dependency-and-reachability
// scan emits the full honest verdict spread (a disqualified dependency, a present-but-absent
// symbol, a reachable-but-untainted control-flow path, and two attacker-tainted ingress→sink
// candidates). It is real code: `go build ./...` succeeds and the binary serves HTTP.
//
// The service exposes a tiny "link preview" style API:
//
//	GET /                   greet in the caller's Accept-Language (the GO-2021-0113 parse surface)
//	GET /healthz            liveness probe
//	GET /preview?target=…   fetch a remote URL and report its status (the SSRF surface)
//	GET /expand?count=…     allocate a working buffer of the requested size (the DoS surface)
//	GET /locale             report the server's default locale
//
// Naming note: nothing user-visible here references the scanner or its brand; this is
// internal fixture code whose externally observable behaviour is an ordinary web service.
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

func main() {
	// Resolve the server's default locale at startup. This reaches the language parser on a
	// compile-time constant — a real control-flow path to the symbol with no external input.
	log.Printf("default locale: %s", defaultLocale())

	mux := http.NewServeMux()
	mux.HandleFunc("/", negotiateHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/preview", fetchHandler)
	mux.HandleFunc("/expand", expandHandler)
	mux.HandleFunc("/locale", localeHandler)

	addr := "127.0.0.1:8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
