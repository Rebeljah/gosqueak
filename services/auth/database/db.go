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
	uid      string
	hashedPw string
	hashSalt string
}

type ErrUserExists struct{ Username string }

func (e ErrUserExists) Error() string {
	return fmt.Sprintf("username: %s already exists", e.Username)
}

type ErrNoSuchUser struct{ Username string }

func (e ErrNoSuchUser) Error() string {
	return fmt.Sprintf("no such username: %s", e.Username)
}

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
		return ErrUserExists{username}
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
	u := User{
		GetUidFor(username),
		getPwHash(password, salt),
		base64.StdEncoding.EncodeToString(salt),
	}

	stmt := "INSERT INTO users (uid, hashedPw, hashSalt) VALUES(?, ?, ?)"

	if _, err := db.Exec(stmt, u.uid, u.hashedPw, u.hashSalt); err != nil {
		return err
	}

	return nil
}

func VerifyPassword(db *sql.DB, username, password string) (bool, error) {
	var u User

	stmt := "SELECT FROM users WHERE uid=?"
	row := db.QueryRow(stmt, GetUidFor(username))

	// return err if the user exists or if row couldn't be read
	if err := row.Scan(&u.uid, &u.hashedPw, &u.hashSalt); err != nil {
		if err == sql.ErrNoRows {
			return false, ErrNoSuchUser{username}
		}
		return false, err
	}

	salt, err := base64.StdEncoding.DecodeString(u.hashSalt)
	if err != nil {
		return false, err
	}

	// prevent timing attack
	if subtle.ConstantTimeCompare(
		[]byte(getPwHash(password, salt)),
		[]byte(u.hashedPw),
	) != 1 {
		return false, nil
	}

	return true, nil
}

func IsValidUsername(usrn string) bool {
	return len(usrn) >= 1 && len(usrn) <= 20
}

func IsValidPassword(pswrd string) bool {
	return len(pswrd) >= 8
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
			hashSalt TEXT NOT NULL
		)
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
	return base64.StdEncoding.EncodeToString(b)
}
