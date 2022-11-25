package main

import (
	"github.com/rebeljah/gosqueak/services/auth"
	"github.com/rebeljah/gosqueak/services/auth/database"
)

const Addr = "127.0.0.1:8081"

func main() {
	db := database.GetDb("../database/users.db")
	serv := auth.NewServer(Addr, db)
	serv.Run()
}
