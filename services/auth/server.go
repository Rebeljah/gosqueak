package auth

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/jwt/rs256"
	"github.com/rebeljah/gosqueak/services/auth/database"
)

// http errors
func errStatusUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Could not authorize", http.StatusUnauthorized)
}

func errInternal(w http.ResponseWriter) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func errBadRequest(w http.ResponseWriter) {
	http.Error(w, "invalid request", http.StatusBadRequest)
}

type Server struct {
	db          *sql.DB
	addr        string
	jwtIssuer   jwt.Issuer
	jwtAudience jwt.Audience
}

func NewServer(addr string, db *sql.DB) *Server {
	issuer := jwt.NewIssuer(
		rs256.ParsePrivate(rs256.LoadKey("../jwtrsa.private")),
		"AUTHSERV",
	)
	audience := jwt.NewAudience(
		issuer.PublicKey(),
		"AUTHSERV",
	)

	return &Server{
		db,
		addr,
		issuer,
		audience,
	}
}

func (s *Server) Run() {
	// set up routes
	http.HandleFunc("/jwtrsa-public", s.handleGetJwtPublicKey)
	http.HandleFunc("/register-user", s.handleRegisterUser)

	// start serving
	log.Fatal(http.ListenAndServe(s.addr, nil))
}

func (s *Server) handleGetJwtPublicKey(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write(x509.MarshalPKCS1PublicKey(s.jwtIssuer.PublicKey()))
	if err != nil {
		errInternal(w)
		return
	}
}

func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		errInternal(w)
		return
	}

	if !database.IsValidUsername(body.Username) {
		errBadRequest(w)
		return
	}

	if !database.IsValidPassword(body.Password) {
		errBadRequest(w)
		return
	}
	
	err = database.RegisterUser(s.db, body.Username, body.Password)
	if err != nil {
		if errors.As(err, &database.ErrUserExists{}) {
			http.Error(w, err.Error(), http.StatusConflict)
		} else {
			errInternal(w)
		}
	}
}
