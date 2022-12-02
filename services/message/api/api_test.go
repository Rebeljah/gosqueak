package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rebeljah/gosqueak/jwt"
	"github.com/rebeljah/gosqueak/jwt/rs256"
	"github.com/rebeljah/gosqueak/services/message/api"
	"github.com/rebeljah/gosqueak/services/message/chat"
	"github.com/rebeljah/gosqueak/services/message/database"
)

const (
	ApiAddr         = "127.0.0.1:8082"
	AuthServerUrl   = "http://127.0.0.1:8081"
	JwtKeyPublicUrl = AuthServerUrl + "/jwtkeypub"
	JwtActorName    = "MESSAGE_API"
)

var db *sql.DB
var serv *api.Server

var iss jwt.Issuer
var aud jwt.Audience

var uidPoster string
var jTokenPoster jwt.Jwt

var uidGetter string
var jTokenGetter jwt.Jwt

func TestMain(m *testing.M) {
	// mock auth server by creating a jwt issuer
	keyPriv := rs256.GeneratePrivateKey()
	iss = jwt.NewIssuer(keyPriv, "AUTHSERV")
	aud = jwt.NewAudience(&keyPriv.PublicKey, JwtActorName)

	db = database.Load("data_test.sqlite")
	defer db.Close()

	// make some "users"
	uidPoster = "test_uid1"
	jTokenPoster = iss.MintToken(uidPoster, JwtActorName, time.Second*10)

	uidGetter = "test_uid2"
	jTokenGetter = iss.MintToken(uidGetter, JwtActorName, time.Second*10)

	// configure server
	serv = api.NewServer(ApiAddr, db, aud, chat.NewRelay(db))
	serv.ConfigureRoutes()

	m.Run()

	// remove db
	os.Remove("data_test.sqlite")
}

func TestPostPreKey(t *testing.T) {
	body := struct {
		Uid     string
		PreKeys []database.PreKey
	}{
		uidPoster,
		[]database.PreKey{database.PreKey{uidPoster, "prekey1", "abc"}},
	}

	// make post body
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err.Error())
	}

	// make request
	bodyBuf := bytes.NewBuffer(b)
	request := httptest.NewRequest("POST", "/prekey", bodyBuf)
	recorder := httptest.NewRecorder()
	request.Header.Set("Authorization", iss.StringifyJwt(jTokenPoster))
	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.FailNow()
	}
}

func TestGetPreKey(t *testing.T) {
	recorder := httptest.NewRecorder()

	request := httptest.NewRequest("GET", "/prekey?fromUid="+uidPoster, nil)
	request.Header.Set("Authorization", iss.StringifyJwt(jTokenGetter))
	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.FailNow()
	}

	var body database.PreKey
	json.Unmarshal(recorder.Body.Bytes(), &body)
	
	if !(body.Key == "prekey1" || body.Key == "prekey2") {
		t.FailNow()
	}
}

func TestPostMessages(t *testing.T) {
	body := []database.Message{database.Message{
		ToUid: uidGetter,
		Private: "secret message",
		KeyId: "7"},
	}
	jsonD, err := json.Marshal(body)

	if err != nil {
		t.Fatalf(err.Error())
	}

	request := httptest.NewRequest("POST", "/message", bytes.NewBuffer(jsonD))
	request.Header.Add("Authorization", iss.StringifyJwt(jTokenPoster))
	recorder := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.FailNow()
	}
}

func TestGetMessages(t *testing.T) {
	database.PostMessages(db, database.Message{
		ToUid: uidGetter,
		Private: "secret message",
		KeyId: "7",
	})

	body := make([]database.Message, 0)

	request := httptest.NewRequest("GET", "/message", nil)
	request.Header.Add("Authorization", iss.StringifyJwt(jTokenGetter))
	recorder := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.FailNow()
	}

	err := json.Unmarshal(recorder.Body.Bytes(), &body)
	if err != nil {
		t.Errorf(err.Error())
	}

	msg := body[0]

	if msg.KeyId != "7" {
		t.Fail()
	}
	if msg.Private != "secret message" {
		t.Fail()
	}
	if msg.ToUid != uidGetter {
		t.Fail()
	}
}
