package handlers

import (
	"net/http"
	"strconv"
)

// parsePagination reads page/page_size query params with sane
// defaults and bounds, shared by every list handler
// (findings/hosts/remediation/audit) so "what's a valid page_size"
// is defined once rather than drifting between endpoints. Invalid or
// out-of-range values fall back to the default rather than erroring
// the request — a malformed page param isn't worth a 400 when
// "just give me page 1" is a perfectly reasonable fallback.
func parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 50

	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			page = n
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 500 {
			pageSize = n
		}
	}
	return page, pageSize
}
