package httpauth

import (
	"net/http"
	"strings"
)

// ExtractBearer returns the token from a standard Authorization header.
func ExtractBearer(h string) string {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// TokenFromRequest returns the bearer token from the request Authorization header.
func TokenFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return ExtractBearer(r.Header.Get("Authorization"))
}
