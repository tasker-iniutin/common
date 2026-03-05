package authsecurity

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessClaims struct {
	UserID uint64 `json:"user_id"`
	jwt.RegisteredClaims
}

type Verifier interface {
	VerifyAccess(tokenStr string) (userID uint64, err error)
}

type Issuer interface {
	NewAccess(userID uint64) (token string, exp time.Time, err error)
	NewRefresh() (token string, hash []byte, err error)
}
