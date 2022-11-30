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

const (
	UserUidLength = 20
)

// models "users" table in DB
type User struct {
	Uid          string
	HashedPw     string
	HashSalt     string
	RefreshToken string
}

// Generate a databse model for a new user
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

//

func GetUidFor(username string) string {
	noSalt := make([]byte, 0, 0)
	return b64Encode(
		hashString(username, noSalt, UserUidLength),
	)
}

func UserExists(db *sql.DB, uid string) (bool, error) {
	stmt := "SELECT uid FROM users WHERE uid=?"
	row := db.QueryRow(stmt, uid)

	if err := row.Scan(new(string)); err != nil {
		if err == sql.ErrNoRows {
			return false, nil // user does not exist
		}
		return false, err // unexpected error
	}
	return true, nil // user exists
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

	// random salt for hashing password
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

// Returns true, nil when the users exists, and the given password hashes to
// the stored password hash.
func VerifyPassword(db *sql.DB, username, password string) (bool, error) {
	var u User

	stmt := "SELECT hashedPw, hashSalt FROM users WHERE uid=?"
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

	// hash the given pass and compare it to stored hash
	if subtle.ConstantTimeCompare(
		[]byte(getPwHash(password, salt)),
		[]byte(u.HashedPw),
	) != 1 { // hash mismatch
		return false, nil
	}

	return true, nil
}

// Set the users refresh token, overwriting the users previous token it it exists.
func SetRefreshToken(db *sql.DB, rft string, uid string) error {
	stmt := "UPDATE users SET refreshToken=? WHERE uid=?"
	_, err := db.Exec(stmt, rft, uid)
	return err
}

// Remove the given token from all users.
// May be called multiple times for same token.
func DiscardRefreshToken(db *sql.DB, rft string) error {
	stmt := "UPDATE users SET refreshToken='' WHERE refreshToken=?"
	_, err := db.Exec(stmt, rft)
	return err
}

// Return true, nil if user exists and has the token in db
func UserHasRefreshToken(db *sql.DB, uid, rfToken string) (bool, error) {
	var token string

	stmt := "SELECT refreshToken FROM users WHERE uid=?"
	err := db.QueryRow(stmt, uid).Scan(&token)

	if err != nil {
		if err == sql.ErrNoRows { // expected error indicates user not exists
			return false, nil
		}
		return false, err // unexpected error
	}

	// user must present the same token as the one in DB
	return token == rfToken, nil
}

// Load the database if it exists, or create a new one at the given path.
func Load(fp string) *sql.DB {
	d, err := sql.Open("sqlite3", fp)
	if err != nil {
		panic(err)
	}

	_, err = d.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			uid TEXT PRIMARY KEY,
			hashedPw TEXT NOT NULL,
			hashSalt TEXT NOT NULL,
			refreshToken TEXT NOT NULL
		);
	`)

	if err != nil {
		panic(err)
	}

	return d
}

func getPwHash(password string, salt []byte) string {
	return b64Encode(hashString(password, salt, UserUidLength))
}

func hashString(s string, salt []byte, keyLen int) []byte {
	return pbkdf2.Key([]byte(s), salt, 4096, keyLen, sha1.New)
}

func b64Encode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
