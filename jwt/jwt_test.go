package jwt_test

import (
	"testing"

	"github.com/rebeljah/gosqueak/jwt"
)

func TestParseJwtString(t *testing.T) {
	j := jwt.New("123")
	k := make([]byte, 256, 256)

	parsed, err := jwt.FromString(j.String(k), k)

	if j != parsed {
		t.Error(err)
	}
}
