package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const DbFileName = "data.sqlite"

// row schema
type User struct {
	Uid string `json:"uid"`
}

type PreKey struct {
	FromUser string `json:"fromUser"`
	Key      string `json:"key"`
}

type Message struct {
	ForUser     string `json:"forUser"`
	PrivateData string `json:"privateData"`
}

//

func Load(fp string) *sql.DB {
	db, err := sql.Open("sqlite3", fp)

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			uid TEXT PRIMARY KEY
		);
		CREATE TABLE IF NOT EXISTS preKeys (
			fromUser TEXT NOT NULL,
			key TEXT UNIQUE NOT NULL,
			FOREIGN KEY (fromUser) REFERENCES users(uid)
		);
		CREATE TABLE IF NOT EXISTS messages (
			forUser TEXT NOT NULL,
			privateData TEXT UNIQUE NOT NULL,
			FOREIGN KEY (forUser) REFERENCES users(uid)
		);
		CREATE INDEX IF NOT EXISTS indexPreKeyFromUser ON preKeys(fromUser);
		CREATE INDEX IF NOT EXISTS indexMessagesForUser ON messages(forUser);
		CREATE INDEX IF NOT EXISTS indexPreKeyKeys ON preKeys(key);
	`)

	if err != nil {
		panic(err)
	}

	return db
}

func GetPreKey(db *sql.DB, fromUser string) (string, error) {
	var preKey PreKey

	stmt := "SELECT FROM preKeys WHERE fromUser=? LIMIT 1"
	row := db.QueryRow(stmt, fromUser)

	err := row.Scan(&preKey.FromUser, &preKey.Key)
	if err != nil {
		return preKey.Key, err
	}

	stmt = "DELETE FROM preKeys WHERE key=? LIMIT 1"
	_, err = db.Exec(stmt, preKey.Key)
	if err != nil {
		return preKey.Key, err
	}

	return preKey.Key, nil
}

func PostPreKeys(db *sql.DB, keys []string, fromUser string) error {
	var stmt string
	args := make([]any, 0, 2*len(keys))

	for _, k := range keys {
		stmt += "INSERT INTO preKeys (fromUser, key) VALUES(?, ?);"
		args = append(args, fromUser, k)
	}

	_, err := db.Exec(stmt, args...)

	return err
}

func GetMessages(db *sql.DB, forUser string) ([]Message, error) {
	messages := make([]Message, 0)

	stmt := "SELECT (privateData) FROM messages WHERE forUser=?"
	rows, err := db.Query(stmt, forUser)

	if err != nil {
		return messages, err
	}

	m := Message{ForUser: forUser}

	for {
		err := rows.Scan(&m.PrivateData)

		if err != nil {
			break
		}

		messages = append(messages, m)
	}

	return messages, nil
}

func PostMessages(db *sql.DB, messages []Message) error {
	var stmt string
	args := make([]any, 0)

	for _, msg := range messages {
		stmt += "INSERT INTO messages (forUser, privateData) VALUES(?, ?)"
		args = append(args, msg.ForUser, msg.PrivateData)
	}

	_, err := db.Exec(stmt, args...)
	return err
}