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
	expectedKeys := []database.PreKey{
		{uidPoster, "pk1", "id1"},
		{uidPoster, "pk2", "id2"},
	}

	// make post body
	b, err := json.Marshal(expectedKeys)
	if err != nil {
		t.Fatal(err.Error())
	}

	// make request
	bodyBuf := bytes.NewBuffer(b)
	request := httptest.NewRequest("POST", "/prekeys", bodyBuf)
	recorder := httptest.NewRecorder()
	request.Header.Set("Authorization", iss.StringifyJwt(jTokenPoster))
	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.Fatalf("Not OK")
	}

	var key string
	postedKeys := make([]string, 0)

	stmt := "SELECT key FROM preKeys WHERE fromUid=?"
	r, err := db.Query(stmt, uidPoster)
	if err != nil {
		t.Fatalf(err.Error())
	}

	for {
		r.Next()
		err = r.Scan(&key)

		if err != nil {
			if len(postedKeys) != 2 {
				t.Fatalf("Did not get %v messages, got %v", len(expectedKeys), len(postedKeys))
			}
			break
		}

		postedKeys = append(postedKeys, key)
	}
}

func TestGetPreKey(t *testing.T) {
	stmt := "INSERT INTO preKeys (fromUid, key, keyId) VALUES(?, ?, ?);"
	db.Exec(stmt, "123", "abc", "1")

	recorder := httptest.NewRecorder()

	request := httptest.NewRequest("GET", "/prekeys?fromUid="+"123", nil)
	request.Header.Set("Authorization", iss.StringifyJwt(jTokenGetter))
	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.Fatalf("Not OK response")
	}

	var body database.PreKey
	json.Unmarshal(recorder.Body.Bytes(), &body)

	if body.Key != "abc" {
		t.Fatalf("wrong key")
	}
}

func TestPostMessages(t *testing.T) {
	body := []database.Message{
		{
			ToUid:   "123",
			Private: "postem",
			KeyId:   "9001"},
		{
			ToUid:   "123",
			Private: "up",
			KeyId:   "9001"},
	}
	jsonD, err := json.Marshal(body)

	if err != nil {
		t.Fatalf(err.Error())
	}

	request := httptest.NewRequest("POST", "/messages", bytes.NewBuffer(jsonD))
	request.Header.Add("Authorization", iss.StringifyJwt(jTokenPoster))
	recorder := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.FailNow()
	}

	stmt := "SELECT private FROM messages WHERE keyId='9001'"
	r, err := db.Query(stmt)

	if err != nil {
		t.FailNow()
	}

	var msg string
	msgs := make([]string, 0)

	for {
		r.Next()
		err = r.Scan(&msg)

		if err != nil {
			if len(msgs) != 2 {
				t.Fatalf("Did not get %v messages, got %v", len(body), len(msgs))
			}
			break
		}

		msgs = append(msgs, msg)
	}

}

func TestGetMessages(t *testing.T) {
	messages := []database.Message{
		{
			ToUid:   uidGetter,
			Private: "msg1",
			KeyId:   "7",
		},
		{
			ToUid:   uidGetter,
			Private: "msg2",
			KeyId:   "7",
		},
	}
	database.PostMessages(db, messages...)

	var body []database.Message
	request := httptest.NewRequest("GET", "/messages", nil)
	request.Header.Add("Authorization", iss.StringifyJwt(jTokenGetter))
	recorder := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(recorder, request)

	if recorder.Result().StatusCode != http.StatusOK {
		t.Log("fail: Status not OK")
		t.FailNow()
	}

	err := json.Unmarshal(recorder.Body.Bytes(), &body)
	if err != nil {
		t.Errorf(err.Error())
	}

	if len(body) != 2 {
		t.Log("did not receive 2 messages")
		t.Fail()
	}

	for _, m := range body {
		if !(m.ToUid == uidGetter && (m.Private == "msg1" || m.Private == "msg2") && m.KeyId == "7") {
			t.Logf("Bad message %v\n", m)
			t.Fail()
		}
	}
}
