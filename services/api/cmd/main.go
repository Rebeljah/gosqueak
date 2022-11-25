package main

import (
	"github.com/rebeljah/gosqueak/services/api"
)

const Addr = "127.0.0.1:8080"

func main() {
	serv := api.NewServer(Addr)
	serv.Run()
}
