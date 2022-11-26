package database

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

type User struct {
	Uid          string
	HashedPw     string
	HashSalt     string
	RefreshToken string
}

func NewUser(username, password string, salt []byte) User {
	return User{
		GetUidFor(username),
		getPwHash(password, salt),
		base64.StdEncoding.EncodeToString(salt),
		"",
	}
}

// errors
type errorUserExists struct{ Username string }

func (e errorUserExists) Error() string {
	return fmt.Sprintf("username: %s already exists", e.Username)
}

type errorNoSuchUser struct{ Username string }

func (e errorNoSuchUser) Error() string {
	return fmt.Sprintf("no such username: %s", e.Username)
}

var ErrUserExists errorUserExists
var ErrNoSuchUser errorNoSuchUser

func UserExists(db *sql.DB, uid string) (bool, error) {
	stmt := "SELECT uid FROM users WHERE uid=?"

	row := db.QueryRow(stmt, uid)

	if err := row.Scan(&uid); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func RegisterUser(db *sql.DB, username, password string) error {
	// err if user exists already
	ok, err := UserExists(db, GetUidFor(username))
	if ok {
		return errorUserExists{username}
	}

	if err != nil {
		return err
	}

	// random salt for hashing
	salt := make([]byte, 16, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// persisted data
	u := NewUser(username, password, salt)

	stmt := "INSERT INTO users (uid, hashedPw, hashSalt, refreshToken) VALUES(?, ?, ?, ?)"

	if _, err := db.Exec(stmt, u.Uid, u.HashedPw, u.HashSalt, u.RefreshToken); err != nil {
		return err
	}

	return nil
}

func VerifyPassword(db *sql.DB, username, password string) (bool, error) {
	var u User

	stmt := "SELECT hashedPw, hashSalt FROM users WHERE uid=? LIMIT 1"
	row := db.QueryRow(stmt, GetUidFor(username))

	// return err if the user exists or if row couldn't be read
	if err := row.Scan(&u.HashedPw, &u.HashSalt); err != nil {
		if err == sql.ErrNoRows {
			return false, errorNoSuchUser{username}
		}
		return false, err
	}

	salt, err := base64.StdEncoding.DecodeString(u.HashSalt)
	if err != nil {
		return false, err
	}

	// prevent timing attack
	if subtle.ConstantTimeCompare(
		[]byte(getPwHash(password, salt)),
		[]byte(u.HashedPw),
	) != 1 {
		return false, nil
	}

	return true, nil
}

func PutRefreshToken(db *sql.DB, rft string, uid string) error {
	stmt := "UPDATE users SET refreshToken=? WHERE uid=? LIMIT 1;"
	_, err := db.Exec(stmt, rft, uid)
	return err
}

func DiscardRefreshToken(db *sql.DB, rft string) error {
	stmt := "UPDATE users SET refreshToken='' WHERE refreshtoken=? LIMIT 1;"
	_, err := db.Exec(stmt, rft)
	return err
}

func IsValidUsername(usrn string) bool {
	return true
}

func IsValidPassword(pswrd string) bool {
	return true
}

func GetUidFor(username string) string {
	return b64Encode(hashString(username, make([]byte, 0, 0)))
}

func GetDb(fp string) *sql.DB {
	d, err := sql.Open("sqlite3", fp)
	if err != nil {
		panic(err)
	}

	d.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			uid TEXT PRIMARY KEY,
			hashedPw TEXT NOT NULL,
			hashSalt TEXT NOT NULL,
			refreshToken TEXT NOT NULL
		);
		CREATE UNQUE INDEX IF NOT EXISTS indexRefreshtokens
		ON users(refreshToken);
	`)

	return d
}

func getPwHash(password string, salt []byte) string {
	return b64Encode(hashString(password, salt))
}

func hashString(s string, salt []byte) []byte {
	return pbkdf2.Key([]byte(s), salt, 4096, 32, sha1.New)
}

func b64Encode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
