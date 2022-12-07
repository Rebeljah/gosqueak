package jwt

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const Alg string = "RS256"
const Typ string = "JWT"

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Body struct {
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Issuer     string `json:"iss"`
	Expiration string `json:"exp"`
	JwtId      string `json:"jti"`
}

type Jwt struct {
	Header    Header
	Body      Body
	Signature []byte
}

// Returns true if the current time is > the exp time of the JWT
func (j Jwt) Expired() bool {
	exp, err := strconv.Atoi(j.Body.Expiration)
	if err != nil {
		panic(err)
	}
	expireTime := time.Unix(int64(exp), 0)

	return time.Now().After(expireTime)
}

// parse JWT from string. Does not verify JWT.
func FromString(j string) (Jwt, error) {
	enc := b64.RawURLEncoding
	parseErr := fmt.Errorf("jwt parse error")
	zeroVal := Jwt{}

	// no-go if there arent 3 parts
	parts := strings.Split(j, ".")
	if len(parts) != 3 {
		return zeroVal, parseErr
	}

	// header not currently needed (default header is always used)
	// header, err := enc.DecodeString(parts[0])
	body, err1 := enc.DecodeString(parts[1])
	sig, err2 := enc.DecodeString(parts[2])
	// if err != nil || err1 != nil || err2 != nil {
	if !(err1 == nil && err2 == nil) {
		return zeroVal, parseErr
	}

	var parsedBody Body
	err := json.Unmarshal(body, &parsedBody)
	if err != nil {
		return zeroVal, parseErr
	}

	return Jwt{Header{Alg, Typ}, parsedBody, sig}, nil
}

type serializable interface {
	Header | Body | Jwt
}

// for converting JWT models into byte slices
func toBytes[t serializable](v t) []byte {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes
}

func NewJwtId() string {
	bytes := make([]byte, 16, 16)
	rand.Read(bytes)

	return fmt.Sprintf("%X", bytes)
}
