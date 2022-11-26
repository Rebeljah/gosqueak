package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/services/auth"
	"github.com/rebeljah/gosqueak/services/auth/database"
)

var db *sql.DB
var serv *auth.Server
var privKey *rsa.PrivateKey
var iss jwt.Issuer
var aud jwt.Audience

func TestHandleGetJwtPublicKey(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/jwtkeypub", nil)

	http.DefaultServeMux.ServeHTTP(recorder, request)

	_, err := x509.ParsePKCS1PublicKey(recorder.Body.Bytes())
	if err != nil {
		t.Error(err)
	}
}

func TestHandleRegisterUser(t *testing.T) {
	rec := httptest.NewRecorder()
	body := `{"username": "test", "password": "testpassword"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))

	http.DefaultServeMux.ServeHTTP(rec, req)

	ok, err := database.UserExists(db, database.GetUidFor("test"))
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Fail()
	}
}

func TestHandlePasswordLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := `{"username": "test", "password": "testpassword"}`
	request := httptest.NewRequest("POST", "/login", strings.NewReader(body))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	refreshToken, err := jwt.Parse(recorder.Body.String())
	if err != nil {
		t.Error(err)
	}

	if refreshToken.Body.Sub != database.GetUidFor("test") {
		t.Fail()
	}
}

func TestHandleMakeJwt(t *testing.T) {
	recorder := httptest.NewRecorder()

	request := httptest.NewRequest("POST", "/jwt?sub=123&aud=321", nil)
	refreshToken := iss.Mint("test", "TEST", "TEST", time.Second)
	request.Header.Set("Authorization", iss.StringifyJwt(refreshToken))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != 200 {
		t.Fail()
	}

	_, err := jwt.Parse(recorder.Body.String())
	if err != nil {
		t.Error(err)
	}
}

func TestHandleLogout(t *testing.T) {
	refreshToken := iss.Mint("test", "TEST", "TEST", time.Second)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/logout", nil)
	request.Header.Set("Authorization", iss.StringifyJwt(refreshToken))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	request = httptest.NewRequest("GET", "/jwt?sub=123&aud=321", nil)
	request.Header.Set("Authorization", iss.StringifyJwt(refreshToken))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	// Fail on success
	if recorder.Result().StatusCode == 200 {
		t.Fail()
	}
}

func TestMain(m *testing.M) {
	setup()
	m.Run()
	tearDown()
}

func setup() {
	db = database.GetDb("users_test.sqlite")
	privKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	iss = jwt.NewIssuer(privKey, "TEST")
	aud = jwt.NewAudience(&privKey.PublicKey, "TEST")

	serv = auth.NewServer(
		"", db, iss, aud,
	)
	serv.ConfigureRoutes()
}

func tearDown() {
	db.Close()
	os.Remove("users_test.sqlite")
}
