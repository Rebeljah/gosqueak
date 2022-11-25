package jwt

import (
	"crypto/rsa"
	b64 "encoding/base64"
	"strings"

	"github.com/rebeljah/gosqueak/jwt/rs256"
)

type Audience struct {
	pub        *rsa.PublicKey
	identifier string
}

func NewAudience(pub *rsa.PublicKey, indentifier string) Audience {
	return Audience{pub, indentifier}
}

func (a Audience) Verify(jwt Jwt) bool {
	if jwt.Expired() || a.identifier != jwt.Body.Aud {
		return false
	}

	return rs256.VerifySignature(
		append(toBytes(jwt.Header), toBytes(jwt.Body)...),
		jwt.Signature,
		a.pub,
	)
}

type Issuer struct {
	priv       *rsa.PrivateKey
	identifier string
}

func NewIssuer(priv *rsa.PrivateKey, indentifier string) Issuer {
	return Issuer{priv, indentifier}
}

func (i Issuer) PublicKey() *rsa.PublicKey {
	return &i.priv.PublicKey
}

func (i Issuer) StringifyJwt(jwt Jwt) string {
	enc := b64.RawURLEncoding

	var parts = make([]string, 3)
	h := toBytes(jwt.Header)
	b := toBytes(jwt.Body)

	parts = append(parts,
		enc.EncodeToString(h),
		enc.EncodeToString(b),
		enc.EncodeToString(rs256.Signature(append(h, b...), i.priv)),
	)

	return strings.Join(parts, ".")
}
