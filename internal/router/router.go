package router

import (
	"net/http"
	"regexp"
	"strings"
)

type Route struct {
	Method  string
	Pattern *regexp.Regexp
	Handler func(http.ResponseWriter, *http.Request, []string)
}

func MatchAndServe(w http.ResponseWriter, r *http.Request, base string, routes []Route) {
	path := r.URL.Path
	if base != "" {
		path = strings.TrimPrefix(path, base)
	}

	for _, rt := range routes {
		if r.Method == rt.Method && rt.Pattern.MatchString(path) {
			matches := rt.Pattern.FindStringSubmatch(path)
			rt.Handler(w, r, matches)
			return
		}
	}
	http.NotFound(w, r)
}
