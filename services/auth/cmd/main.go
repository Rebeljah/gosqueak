package main

import (
	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/jwt/rs256"
	"github.com/rebeljah/gosqueak/services/auth/api"
	"github.com/rebeljah/gosqueak/services/auth/database"
)

const (
	Addr       = "127.0.0.1:8081"
	JwtActorId = "AUTHSERV"
)

func main() {
	db := database.Load("users.sqlite")

	iss := jwt.NewIssuer(
		rs256.ParsePrivate(rs256.LoadKey("jwtrsa.private")),
		JwtActorId,
	)
	aud := jwt.NewAudience(
		iss.PublicKey(), 
		JwtActorId,
	)

	serv := api.NewServer(Addr, db, iss, aud)
	serv.Run()
}
