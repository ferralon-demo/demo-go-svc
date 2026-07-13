package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

// beaconFault is reached only from expandHandler's fault-recovery path, so reaching it proves
// the unbounded allocation actually faulted. It reads the planted seed and surfaces it to the
// out-of-band endpoint, which is how a live fire observes the resource-exhaustion fault firing.
// A normal (small) count returns OK without ever entering recover, so it never beacons.
func beaconFault() {
	oob := os.Getenv("TEGRON_OOB_URL")
	if oob == "" {
		return
	}
	seed, err := os.ReadFile(canarySeedPath)
	if err != nil {
		return
	}
	resp, err := http.Get(oob + "?kind=fault&data=" + string(seed))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

// expandHandler implements a buffer-sizing endpoint. It sizes an allocation directly from the
// caller-supplied `count` with no upper bound, so a large count drives an allocation the
// runtime cannot satisfy and the process faults — uncontrolled resource consumption (CWE-400).
// The attacker-controlled `count` query parameter flows straight into make([]byte, n).
//
// A count at/near math.MaxInt64 trips Go's recoverable "makeslice: len out of range" panic
// (host-RAM-independent), which the deferred recover catches; that recover path is the only
// place the seed is read. A merely large count would instead drive an unrecoverable OS OOM
// that kills the process before recover runs, so the trigger must drive count near MaxInt64.
func expandHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()

	defer func() {
		if rec := recover(); rec != nil {
			// Reached only when the unbounded allocation faulted (the CWE-400 fault).
			beaconFault()
			http.Error(w, "allocation failed", http.StatusInternalServerError)
		}
	}()

	n, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil {
		http.Error(w, "invalid count", http.StatusBadRequest)
		return
	}

	if n < 0 || n > 1<<20 {
		http.Error(w, "count out of range", http.StatusBadRequest)
		return
	}

	// DoS sink: an attacker-sized allocation with no upper bound.
	buf := make([]byte, n)
	fmt.Fprintf(w, "allocated %d bytes\n", len(buf))
}
