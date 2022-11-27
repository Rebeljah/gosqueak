package api

import (
	"log"
	"net/http"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/jwt/rs256"
)

const (
	AuthServerUrl      = "http://127.0.0.1:8081"
	JwtRsaPublicKeyUrl = AuthServerUrl + "/jwtkeypub"
	MsgServerUrl       = "http://127.0.0.1:8082"
	JwtActorName       = "APISERV"
)

func errStatusUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Could not authorize", http.StatusUnauthorized)
}

func errInternal(w http.ResponseWriter) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

type Server struct {
	addr        string
	jwtAudience jwt.Audience
}

func NewServer(addr string) *Server {
	pub := rs256.FetchRsaPublicKey(JwtRsaPublicKeyUrl)
	return &Server{addr, jwt.NewAudience(pub, JwtActorName)}
}

func (s *Server) Run() {
	// set up routes
	http.HandleFunc("/jwt-aud-name", s.handleGetJwtAudName)
	http.HandleFunc("/msg-server-url", s.handleGetMsgServerUrl)

	// start serving
	log.Fatal(http.ListenAndServe(s.addr, nil))
}

// returns the TCP address of the sock server in form <ip>:<port>
func (s *Server) handleGetMsgServerUrl(w http.ResponseWriter, r *http.Request) {
	addr := []byte(MsgServerUrl)

	if _, err := w.Write(addr); err != nil {
		errInternal(w)
		return
	}
}

func (s *Server) handleGetJwtAudName(w http.ResponseWriter, r *http.Request) {
	addr := []byte(JwtActorName)

	if _, err := w.Write(addr); err != nil {
		errInternal(w)
		return
	}
}
