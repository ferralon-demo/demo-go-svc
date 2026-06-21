package main

import (
	"fmt"
	"net/http"
	"strconv"
)

// expandHandler implements a buffer-sizing endpoint. It sizes an allocation directly from the
// caller-supplied `count` with no upper bound, so a large count drives an allocation the
// runtime cannot satisfy and the process faults — uncontrolled resource consumption (CWE-400).
// The attacker-controlled `count` query parameter flows straight into make([]byte, n).
func expandHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()

	n, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil {
		http.Error(w, "invalid count", http.StatusBadRequest)
		return
	}

	// DoS sink: an attacker-sized allocation with no upper bound.
	buf := make([]byte, n)
	fmt.Fprintf(w, "allocated %d bytes\n", len(buf))
}
