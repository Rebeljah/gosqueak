package main

import (
	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/jwt/rs256"
	"github.com/rebeljah/gosqueak/services/ecdh/api"
	"github.com/rebeljah/gosqueak/services/ecdh/database"
)

const (
	AuthServerUrl   = "http://127.0.0.1:8081"
	JwtKeyPublicUrl = AuthServerUrl + "/jwtkeypub"
	AudIdentifier   = "ECDH"
)

func main() {
	db := database.Load("data.sqlite")
	aud := jwt.NewAudience(rs256.FetchRsaPublicKey(JwtKeyPublicUrl), AudIdentifier)
	serv := api.NewServer("127.0.0.1:8083", db, aud)

	serv.Run()
}
