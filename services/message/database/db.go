package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const DbFileName = "data.sqlite"

// row schema
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
		CREATE TABLE IF NOT EXISTS messages (
			toUid TEXT NOT NULL,
			private TEXT UNIQUE NOT NULL,
			keyId STRING NOT NULL
		);
		CREATE INDEX IF NOT EXISTS indexMessagesToUid ON messages(toUid);
	`)

	if err != nil {
		panic(err)
	}

	return db
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
