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
	KeyId   string `json:"keyId"`
}

type Message struct {
	ToUid   string `json:"toUid"`
	Private string `json:"private"`
	KeyId   string `json:"keyId"`
}

//

func Load(fp string) *sql.DB {
	db, err := sql.Open("sqlite3", fp)

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS preKeys (
			fromUid TEXT NOT NULL,
			key TEXT UNIQUE NOT NULL,
			keyId TEXT PRIMARY KEY
		);
		CREATE TABLE IF NOT EXISTS messages (
			toUid TEXT NOT NULL,
			private TEXT UNIQUE NOT NULL,
			keyId STRING NOT NULL
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

func GetPreKey(db *sql.DB, fromUid string) (PreKey, error) {
	var preKey PreKey

	stmt := "SELECT keyId, fromUid, key FROM preKeys WHERE fromUid=?"
	row := db.QueryRow(stmt, fromUid)

	err := row.Scan(&preKey.KeyId, &preKey.FromUid, &preKey.Key)
	if err != nil {
		return preKey, err
	}

	stmt = "DELETE FROM preKeys WHERE key=?"
	_, err = db.Exec(stmt, preKey.Key)
	if err != nil {
		return preKey, err
	}

	return preKey, nil
}

func PostPreKeys(db *sql.DB, keys []PreKey) error {
	var stmt string
	args := make([]any, 0, 3*len(keys))

	for _, k := range keys {
		stmt += "INSERT INTO preKeys (fromUid, key, keyId) VALUES(?, ?, ?);"
		args = append(args, k.FromUid, k.Key, k.KeyId)
	}

	_, err := db.Exec(stmt, args...)

	return err
}

func GetMessages(db *sql.DB, toUid string) ([]Message, error) {
	messages := make([]Message, 0)

	stmt := "SELECT private, keyId FROM messages WHERE toUid=?"
	rows, err := db.Query(stmt, toUid)

	if err != nil {
		return messages, err
	}

	m := Message{ToUid: toUid}

	for {
		if ok := rows.Next(); !ok {
			break
		}

		err := rows.Scan(&m.Private, &m.KeyId)

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
		stmt += "INSERT INTO messages (toUid, private, keyId) VALUES(?, ?, ?);"
		args = append(args, msg.ToUid, msg.Private, msg.KeyId)
	}

	_, err := db.Exec(stmt, args...)
	return err
}
