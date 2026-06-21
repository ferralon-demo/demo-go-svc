package main

import (
	"net/http"

	"golang.org/x/text/language"
)

// defaultLocale parses a compile-time-constant BCP-47 tag. It reaches language.Parse on a
// reachable control-flow path from main, but no externally supplied data ever flows to it —
// the argument is a fixed string. This is a reachable-but-untainted use of the symbol.
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
