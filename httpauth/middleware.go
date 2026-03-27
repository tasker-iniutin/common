package httpauth

import (
	"net/http"

	"github.com/tasker-iniutin/common/authctx"
)

type Verifier interface {
	VerifyAccess(tokenStr string) (userID uint64, err error)
}

// Middleware for authorization checking and adding user_id in ctx
func AuthJWT(next http.Handler, v Verifier, whitelist map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if _, ok := whitelist[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}

		token := ExtractBearer(r.Header.Get("Authorization"))
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		userID, err := v.VerifyAccess(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := authctx.WithUserID(r.Context(), userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
