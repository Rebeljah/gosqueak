package api_test

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
	"github.com/rebeljah/gosqueak/services/auth/api"
	"github.com/rebeljah/gosqueak/services/auth/database"
)

var db *sql.DB
var serv *api.Server
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
	body := `{"username": "testusername", "password": "testpassword"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))

	http.DefaultServeMux.ServeHTTP(rec, req)

	ok, err := database.UserExists(db, database.GetUidFor("testusername"))
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Fail()
	}
}

func TestHandlePasswordLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := `{"username": "testusername", "password": "testpassword"}`
	request := httptest.NewRequest("POST", "/login", strings.NewReader(body))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	refreshToken, err := jwt.Parse(recorder.Body.String())
	if err != nil {
		t.Error(err)
	}

	if refreshToken.Body.Sub != database.GetUidFor("testusername") {
		t.Fail()
	}
}

func TestHandleMakeJwt(t *testing.T) {
	uid := database.GetUidFor("testusername")
	refreshToken := iss.MintToken(uid, "TEST", time.Second)
	rftString := iss.StringifyJwt(refreshToken)

	database.SetRefreshToken(db, rftString, uid)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/jwt?aud=service", nil)
	request.Header.Set("Authorization", rftString)

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != 200 {
		t.FailNow()
	}

	_, err := jwt.Parse(recorder.Body.String())
	if err != nil {
		t.Error(err)
	}
}

func TestHandleLogout(t *testing.T) {
	refreshToken := iss.MintToken("testuid", "TEST", time.Second)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/logout", nil)
	request.Header.Set("Authorization", iss.StringifyJwt(refreshToken))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	request = httptest.NewRequest("GET", "/jwt?aud=321", nil)
	request.Header.Set("Authorization", iss.StringifyJwt(refreshToken))

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Fail()
	}
}

func TestMain(m *testing.M) {
	setup()
	m.Run()
	tearDown()
}

func setup() {
	db = database.Load("users_test.sqlite")
	privKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	iss = jwt.NewIssuer(privKey, "TEST")
	aud = jwt.NewAudience(&privKey.PublicKey, "TEST")

	serv = api.NewServer(
		"", db, iss, aud,
	)
	serv.ConfigureRoutes()
}

func tearDown() {
	db.Close()
	os.Remove("users_test.sqlite")
}
