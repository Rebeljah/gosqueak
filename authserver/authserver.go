package authserver

import (
	"log"
	"net/http"
)

const (
	addr = "localhost:8081"
)

var jwtKey []byte

func errStatusUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Could not authorize", http.StatusUnauthorized)
}

func errInternal(w http.ResponseWriter) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// Return RSA public key used to verify JWT signatures
func handleGetJwtPublicKey(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

func Init() {
	// set up routes
	http.HandleFunc("/jwt-public-key", handleGetJwtPublicKey)

	// start serving
	log.Fatal(http.ListenAndServe(addr, nil))
}
