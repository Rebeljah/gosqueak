package api

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/services/auth/database"
)

const (
	RefreshTokenTTL = time.Hour * 24 * 7
	JwtTTL          = time.Second * 5
)

type HandlerFunction func(http.ResponseWriter, *http.Request)

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

func NewServer(addr string, db *sql.DB, iss jwt.Issuer, aud jwt.Audience) *Server {
	return &Server{db, addr, iss, aud}
}

func (s *Server) ConfigureRoutes() {
	http.HandleFunc("/jwtkeypub", s.handleGetJwtPublicKey)
	http.HandleFunc("/register", s.handleRegisterUser)
	http.HandleFunc("/logout", AuthRefreshToken(s, s.handleLogout))
	http.HandleFunc("/login", s.handlePasswordLogin)
	http.HandleFunc("/jwt", AuthRefreshToken(s, s.HandleMakeJwt))
}

func (s *Server) Run() {
	s.ConfigureRoutes()
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
		errBadRequest(w)
		return
	}

	err = database.RegisterUser(s.db, body.Username, body.Password)
	if err != nil {
		if errors.As(err, &database.ErrUserExists) {
			http.Error(w, err.Error(), http.StatusConflict)
		} else {
			errInternal(w)
		}
	}
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// read body and validate
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		errBadRequest(w)
		return
	}

	ok, err := database.VerifyPassword(s.db, body.Username, body.Password)
	if err != nil {
		if errors.As(err, &database.ErrNoSuchUser) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		errInternal(w)
		return
	}

	if !ok {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	// Set a new refresh token
	rfToken := s.jwtIssuer.MintToken(
		database.GetUidFor(body.Username),
		s.jwtIssuer.Name,
		RefreshTokenTTL,
	)
	rft := s.jwtIssuer.StringifyJwt(rfToken)
	database.SetRefreshToken(s.db, rft, rfToken.Body.Subject)

	// write refresh token back as response
	_, err = w.Write([]byte(rft))

	if err != nil {
		errInternal(w)
	}
}

func (s *Server) HandleMakeJwt(w http.ResponseWriter, r *http.Request) {
	rfToken, _ := jwt.FromString(r.Header.Get("Authorization"))

	// requested audience
	aud := r.URL.Query().Get("aud")
	if aud == "" {
		errBadRequest(w)
		return
	}

	j := s.jwtIssuer.MintToken(rfToken.Body.Subject, aud, JwtTTL)

	w.Write([]byte(s.jwtIssuer.StringifyJwt(j)))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// idempotent token delete
	err := database.DiscardRefreshToken(s.db, r.Header.Get("Authorization"))
	if err != nil {
		errInternal(w)
	}
}

// Refresh token auth middleware for handlers;
// This middleware checks that the token is valid, verified, and current, and that
// the token exists in the database (not revoked) and belongs to the user.
func AuthRefreshToken(s *Server, handler HandlerFunction) HandlerFunction {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		token, err := jwt.FromString(tokenString)
		if err != nil {
			errStatusUnauthorized(w)
			return
		}

		// Make sure the rft can be signature verified
		if !s.jwtAudience.JwtIsValid(token) {
			errStatusUnauthorized(w)
			return
		}

		// delete rft from DB and return 401 if the refresh token expired
		if token.Expired() {
			database.DiscardRefreshToken(s.db, tokenString)
			errStatusUnauthorized(w)
			return
		}

		// make sure that token hasn't been revoked
		ok, err := database.UserHasRefreshToken(s.db, token.Body.Subject, tokenString)
		if err != nil {
			errInternal(w)
			return
		}
		if !ok {
			errStatusUnauthorized(w)
			return
		}

		// Token verified, run next handler
		handler(w, r)
	}
}
