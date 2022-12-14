package database_test

import (
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/rebeljah/gosqueak/services/auth/database"
)

var db *sql.DB

func TestUserExists(t *testing.T) {
	username := fmt.Sprintf("%X", rand.Uint32())
	password := fmt.Sprintf("%X", rand.Uint32())
	user := addUserToDb(db, username, password)

	// test logic
	ok, err := database.UserExists(db, user.Uid)
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.FailNow()
	}
}

func TestRegisterUser(t *testing.T) {
	username := fmt.Sprintf("%X", rand.Uint32())
	password := fmt.Sprintf("%X", rand.Uint32())
	user := database.NewUser(username, password, []byte(username+password))

	err := database.RegisterUser(
		db, username, password,
	)

	if err != nil {
		t.Error(err)
	}

	var uid string
	stmt := "SELECT uid FROM users WHERE uid=? LIMIT 1"
	row := db.QueryRow(stmt, user.Uid)
	err = row.Scan(&uid)

	if err != nil {
		t.Error(err)
	}
}

func TestVerifyPassword(t *testing.T) {
	username := fmt.Sprintf("%X", rand.Uint32())
	password := fmt.Sprintf("%X", rand.Uint32())
	addUserToDb(db, username, password)

	ok, err := database.VerifyPassword(db, username, password)
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.FailNow()
	}
}

func TestVerifyPasswordFails(t *testing.T) {
	addUserToDb(db, "user", "pass")

	ok, err := database.VerifyPassword(db, "user", "wrongpass")
	if err != nil {
		t.Error(err)
	}

	if ok {
		t.FailNow()
	}
}

func TestUserHasRefreshToken(t *testing.T) {
	stmt := `
		INSERT INTO users (uid, hashedPw, hashSalt, refreshToken)
		VALUES('123', 'abc', '123', 'token')
	`
	db.Exec(stmt)

	ok, err := database.UserHasRefreshToken(db, "123", "token")
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.FailNow()
	}
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	tearDown()

	os.Exit(code)
}

func setup() {
	db = database.Load("users_test.sqlite")
}

func tearDown() {
	os.Remove("users_test.sqlite")
}

func addUserToDb(db *sql.DB, username, password string) database.User {
	user := database.NewUser(username, password, []byte(username+password))
	db.Exec(
		"INSERT INTO users (uid, hashedPw, hashSalt, refreshToken) VALUES(?,?,?,?)",
		user.Uid, user.HashedPw, user.HashSalt, user.RefreshToken,
	)

	return user
}
