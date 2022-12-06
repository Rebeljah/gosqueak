package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// row schema
type PreKey struct {
	FromUid string `json:"fromUid"`
	Key     string `json:"key"`
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
		CREATE INDEX IF NOT EXISTS indexPreKeyFromUid ON preKeys(fromUid);
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
