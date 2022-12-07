package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/services/ecdh/database"
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
	jwtAudience jwt.Audience
}

func NewServer(addr string, db *sql.DB, aud jwt.Audience) *Server {
	return &Server{db, addr, aud}
}

func (s *Server) ConfigureRoutes() {
	http.HandleFunc("/prekeys", Log(JwtMiddleware(s, s.handlePreKey)))
}

func (s *Server) Run() {
	s.ConfigureRoutes()
	// start serving
	log.Fatal(http.ListenAndServe(s.addr, nil))
}

// GET: look for the uid in query parameters and respond with
// one of the requested users stored public keys.
//
// POST: read uid and keys from request body, then store the keys in the DB.
func (s *Server) handlePreKey(w http.ResponseWriter, r *http.Request) {
	jToken := r.Context().Value("jwt").(jwt.Jwt)

	switch r.Method {
	case http.MethodGet:
		uid := r.URL.Query().Get("fromUid")

		if uid == "" {
			errBadRequest(w)
			return
		}

		preKey, err := database.GetPreKey(s.db, uid)

		if err != nil {
			errInternal(w)
			return
		}

		body, err := json.Marshal(preKey)

		if err != nil {
			errInternal(w)
			return
		}

		_, err = w.Write(body)

		if err != nil {
			errInternal(w)
		}

	case http.MethodPost:
		var body []database.PreKey

		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&body)

		if err != nil {
			errBadRequest(w)
			return
		}

		// client must send at least one prekey
		if len(body) < 1 {
			errBadRequest(w)
			return
		}

		// prevent adding keys for other users
		if body[0].FromUid != jToken.Body.Subject {
			errStatusUnauthorized(w)
			return
		}

		err = database.PostPreKeys(s.db, body)

		if err != nil {
			errInternal(w)
		}
		return

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func JwtMiddleware(s *Server, handler HandlerFunction) HandlerFunction {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := jwt.FromString(r.Header.Get("Authorization"))

		if err != nil || !s.jwtAudience.JwtIsValid(j) || j.Expired() {
			errStatusUnauthorized(w)
			return
		}

		// Add JWT as context to the request.
		r = r.WithContext(context.WithValue(r.Context(), "jwt", j))
		handler(w, r)
	}
}

func Log(handler HandlerFunction) HandlerFunction {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%v] - %v\n", r.Method, r.URL.String())
		handler(w, r)
	}
}
