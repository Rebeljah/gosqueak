package jwt

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"crypto/rand"
	"strconv"
	"strings"
	"time"
)

const Alg string = "RS256"
const Typ string = "JWT"

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Body struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iss string `json:"iss"`
	Exp string `json:"exp"`
	Jti string `json:"jti"`
}

type Jwt struct {
	Header    Header
	Body      Body
	Signature []byte
}

func (j Jwt) Expired() bool {
	seconds, err := strconv.Atoi(j.Body.Exp)
	if err != nil {
		panic(err)
	}

	exp := time.Unix(int64(seconds), 0)

	return time.Now().After(exp)
}

func Parse(j string) (Jwt, error) {
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

func RefreshToken(sub, iss, aud string, durationSeconds int) Jwt {
	exp := strconv.Itoa(int(
		time.Now().Add(
			time.Duration(durationSeconds) * time.Second).Unix(),
		),
	)

	return Jwt{
		Header{Alg, Typ},
		Body{sub, aud, iss, exp, NewJwtId()},
		make([]byte, 0),
	}
}
