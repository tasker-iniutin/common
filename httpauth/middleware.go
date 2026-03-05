package httpauth

import (
	"net/http"
	"strings"
)

type Verifier interface {
	VerifyAccess(tokenStr string) (userID uint64, err error)
}

func AuthJWT(next http.Handler, v Verifier, whitelist map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := whitelist[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}

		token := extractBearer(r.Header.Get("Authorization"))
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		if _, err := v.VerifyAccess(token); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func extractBearer(h string) string {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
