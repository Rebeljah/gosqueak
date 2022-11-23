package jwt_test

import (
	"testing"

	"github.com/rebeljah/squeek/jwt"
)

func TestParseJWTString(t *testing.T) {
	j := jwt.NewJWT("123")
	k := make([]byte, 256, 256)

	parsed, err := jwt.JWTFromString(j.String(k), k)

	if j != parsed {
		t.Error(err)
	}
}
