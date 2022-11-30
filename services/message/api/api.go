package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/services/message/chat"
	"github.com/rebeljah/gosqueak/services/message/database"
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
	msgRelay    chat.Relay
}

func NewServer(addr string, db *sql.DB, aud jwt.Audience, msgRelay chat.Relay) *Server {
	return &Server{db, addr, aud, msgRelay}
}

func (s *Server) ConfigureRoutes() {
	http.HandleFunc("/prekey", JwtMiddleware(s, s.preKey))
	http.HandleFunc("/message", JwtMiddleware(s, s.asyncMessage))
	http.HandleFunc("/chat", JwtMiddleware(s, s.upgradeConnection))
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
func (s *Server) preKey(w http.ResponseWriter, r *http.Request) {
	jToken := r.Context().Value("jwt").(jwt.Jwt)

	switch r.Method {
	case http.MethodGet:
		uid := r.URL.Query().Get("fromUser")

		if uid == "" {
			errBadRequest(w)
			return
		}

		preKey, err := database.GetPreKey(s.db, uid)

		if err != nil {
			errInternal(w)
			return
		}

		_, err = w.Write([]byte(preKey))

		if err != nil {
			errInternal(w)
		}

	case http.MethodPost:
		var body struct {
			Uid     string   `json:"uid"`
			PreKeys []string `json:"preKeys"`
		}
		
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&body)

		if err != nil {
			errBadRequest(w)
			return
		}

		// prevent adding keys for other users
		if jToken.Body.Subject != body.Uid {
			errStatusUnauthorized(w)
			return
		}

		err = database.PostPreKeys(s.db, body.PreKeys, body.Uid)

		if err != nil {
			errInternal(w)
		}
		return

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) asyncMessage(w http.ResponseWriter, r *http.Request) {
	jToken := r.Context().Value("jwt").(jwt.Jwt)

	var body struct {
		Messages []database.Message `json:"messages"`
	}

	switch r.Method {
	case http.MethodGet:
		// user posseses JWT, so should be allowed to get messages for jwt sub
		messages, err := database.GetMessages(s.db, jToken.Body.Subject)

		if err != nil {
			errInternal(w)
			return
		}

		body.Messages = messages
		err = json.NewEncoder(w).Encode(body)

		if err != nil {
			errInternal(w)
		}

	case http.MethodPost:
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&body)

		if err != nil {
			errBadRequest(w)
			return
		}

		err = database.PostMessages(s.db, body.Messages)

		if err != nil {
			errInternal(w)
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) upgradeConnection(w http.ResponseWriter, r *http.Request) {
	jToken := r.Context().Value("jwt").(jwt.Jwt)
	conn, _, _ := w.(http.Hijacker).Hijack()
	s.msgRelay.HandleUserConnection(jToken.Body.Subject, conn)
}

func JwtMiddleware(s *Server, handler HandlerFunction) HandlerFunction {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := jwt.FromString(r.Header.Get("Authorization"))

		if err != nil || j.Expired() || !s.jwtAudience.JwtIsValid(j) {
			errStatusUnauthorized(w)
			return
		}

		// Add JWT as context to the request.
		r = r.WithContext(context.WithValue(r.Context(), "jwt", j))
		handler(w, r)
	}
}
