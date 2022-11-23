package jwt

import (
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const ALG string = "RS256"
const TYP string = "JWT"


type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JwtBody struct {
	Sub string `json:"sub"`
}

type Jwt struct {
	Header JwtHeader
	Body   JwtBody
}

type serializable interface {
	JwtHeader | JwtBody | Jwt
}

func New(sub string) Jwt {
	return Jwt{
		Header: JwtHeader{ALG, TYP},
		Body:   JwtBody{sub},
	}
}

// signs the header+body and returns a signed JWT string
func (j Jwt) String(jwtKey []byte) string {
	enc := b64.RawURLEncoding

	header := toBytes(j.Header)
	body := toBytes(j.Body)
	signature := j.Signature(jwtKey)

	parts := []string{
		enc.EncodeToString(header),
		enc.EncodeToString(body),
		enc.EncodeToString(signature),
	}

	return strings.Join(parts, ".")
}

// generate a HMAC signature of header and body
func (j Jwt) Signature(jwtKey []byte) []byte {
	panic("not implemented")
}

// return true if the signatures match (timing attack safe)
func (j Jwt) VerifySignature(claimSignature, jwtKey []byte) bool {
	panic("not implemented")
}

// Verifies the JWT string signature and returns a JWT with header and body
func FromString(j string, jwtKey []byte) (Jwt, error) {
	enc := b64.RawURLEncoding
	parseErr := fmt.Errorf("jwt parse error")
	verifyErr := fmt.Errorf("could not verify jwt signature")
	zeroVal := Jwt{}

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

	var parsedBody JwtBody
	err := json.Unmarshal(body, &parsedBody)
	if err != nil {
		return zeroVal, parseErr
	}

	jwt := New(parsedBody.Sub)

	if !jwt.VerifySignature(claimSignature, jwtKey) {
		return zeroVal, verifyErr
	}

	return jwt, nil
}

func FetchRsaPublicKey(rsaKeyAddress string) []byte {
	r, err := http.Get(rsaKeyAddress)
	if err != nil {
		panic(err)
	}

	jwtKeyB64 := make([]byte, 1024)

	n, err := r.Body.Read(jwtKeyB64)
	if err != nil {
		panic(err)
	}

	jwtKeyBytes := make([]byte, 512, 512)

	n, err = base64.StdEncoding.Decode(jwtKeyBytes, jwtKeyB64)
	if err != nil {
		panic(err)
	}

	if (n != 256) && (n != 512) {
		panic(fmt.Errorf("invalid key size: %d", n))
	}

	jwtKeyBytes = jwtKeyBytes[:n]

	return jwtKeyBytes
}

// for converting JWT models into byte slices
func toBytes[t serializable](v t) []byte {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes
}
