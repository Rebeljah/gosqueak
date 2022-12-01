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
	FromUid string `json:"fromUid"`
	Key     string `json:"key"`
}

type Message struct {
	ToUid   string `json:"toUid"`
	Private string `json:"private"`
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
			fromUid TEXT NOT NULL,
			key TEXT UNIQUE NOT NULL,
			FOREIGN KEY (fromUid) REFERENCES users(uid)
		);
		CREATE TABLE IF NOT EXISTS messages (
			toUid TEXT NOT NULL,
			private TEXT UNIQUE NOT NULL,
			FOREIGN KEY (toUid) REFERENCES users(uid)
		);
		CREATE INDEX IF NOT EXISTS indexPreKeyFromUid ON preKeys(fromUid);
		CREATE INDEX IF NOT EXISTS indexMessagesToUid ON messages(toUid);
		CREATE INDEX IF NOT EXISTS indexPreKeyKeys ON preKeys(key);
	`)

	if err != nil {
		panic(err)
	}

	return db
}

func GetPreKey(db *sql.DB, fromUser string) (string, error) {
	var preKey PreKey

	stmt := "SELECT FROM preKeys WHERE fromUid=? LIMIT 1"
	row := db.QueryRow(stmt, fromUser)

	err := row.Scan(&preKey.FromUid, &preKey.Key)
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

func PostPreKeys(db *sql.DB, keys []string, fromUid string) error {
	var stmt string
	args := make([]any, 0, 2*len(keys))

	for _, k := range keys {
		stmt += "INSERT INTO preKeys (fromUid, key) VALUES(?, ?);"
		args = append(args, fromUid, k)
	}

	_, err := db.Exec(stmt, args...)

	return err
}

func GetMessages(db *sql.DB, toUid string) ([]Message, error) {
	messages := make([]Message, 0)

	stmt := "SELECT (private) FROM messages WHERE forUid=?"
	rows, err := db.Query(stmt, toUid)

	if err != nil {
		return messages, err
	}

	m := Message{ToUid: toUid}

	for {
		err := rows.Scan(&m.Private)

		if err != nil {
			break
		}

		messages = append(messages, m)
	}

	return messages, nil
}

func PostMessages(db *sql.DB, messages ...Message) error {
	var stmt string
	args := make([]any, 0)

	for _, msg := range messages {
		stmt += "INSERT INTO messages (toUid, private) VALUES(?, ?)"
		args = append(args, msg.ToUid, msg.Private)
	}

	_, err := db.Exec(stmt, args...)
	return err
}
