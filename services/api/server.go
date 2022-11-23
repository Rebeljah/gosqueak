package api

import (
	"log"
	"net/http"

	"github.com/rebeljah/gosqueak/jwt"
)

const (
	addr       = "localhost:8080"
	tcpAddress = "localhost:8000"
)

var jwtKey []byte

func errStatusUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Could not authorize", http.StatusUnauthorized)
}

func errInternal(w http.ResponseWriter) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// returns the TCP address of the sock server in form <ip>:<port>
func handleGetTcpAddr(w http.ResponseWriter, r *http.Request) {
	// verify jwt from incoming req
	// only care about success or failure
	_, err := jwt.FromString(r.Header.Get("jwt"), jwtKey)
	if err != nil {
		errStatusUnauthorized(w)
		return
	}

	if _, err := w.Write([]byte(tcpAddress)); err != nil {
		errInternal(w)
		return
	}
}

func Init() {
	// to verify JWT signatures
	jwtKey = jwt.FetchRsaPublicKey()

	// set up routes
	http.HandleFunc("/tcp-addr", handleGetTcpAddr)

	// start serving
	log.Fatal(http.ListenAndServe(addr, nil))
}
