package jwt

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const ALG string = "RS256"
const TYP string = "JWT"

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTBody struct {
	Sub string `json:"sub"`
}

type JWT struct {
	Header JWTHeader
	Body   JWTBody
}

type serializable interface {
	JWTHeader | JWTBody | JWT
}

func NewJWT(sub string) JWT {
	return JWT{
		Header: JWTHeader{ALG, TYP},
		Body:   JWTBody{sub},
	}
}

// signs the header+body and returns a signed JWT string
func (self JWT) String(jwtKey []byte) string {
	enc := b64.RawURLEncoding

	header := toBytes(self.Header)
	body := toBytes(self.Body)
	signature := self.Signature(jwtKey)

	parts := []string{
		enc.EncodeToString(header),
		enc.EncodeToString(body),
		enc.EncodeToString(signature),
	}

	return strings.Join(parts, ".")
}

// generate a HMAC signature of header and body
func (self JWT) Signature(jwtKey []byte) []byte {
	panic("not implemented")
}

// return true if the signatures match (timing attack safe)
func (self JWT) VerifySignature(claimSignature, jwtKey []byte) bool {
	panic("not implemented")
}

// Verifies the JWT string signature and returns a JWT with header and body
func JWTFromString(j string, jwtKey []byte) (JWT, error) {
	enc := b64.RawURLEncoding
	parseErr := fmt.Errorf("jwt parse error")
	verifyErr := fmt.Errorf("could not verify jwt signature")
	zeroVal := JWT{}

	// no-go if there arent 3 parts
	parts := strings.Split(j, ".")
	if len(parts) != 3 {
		return zeroVal, parseErr
	}

	// header not currently needed (default header is always used)
	// header, err := enc.DecodeString(parts[0])
	body, err1 := enc.DecodeString(parts[1])
	claimSignature, err2 := enc.DecodeString(parts[2])
	// if err != nil || err1 != nil || err2 != nil {
	if err1 != nil || err2 != nil {
		return zeroVal, parseErr
	}

	var parsedBody JWTBody
	err := json.Unmarshal(body, &parsedBody)
	if err != nil {
		return zeroVal, parseErr
	}

	jwt := NewJWT(parsedBody.Sub)

	if !jwt.VerifySignature(claimSignature, jwtKey) {
		return zeroVal, verifyErr
	}

	return jwt, nil
}

// for converting JWT models into byte slices
func toBytes[t serializable](v t) []byte {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes
}
