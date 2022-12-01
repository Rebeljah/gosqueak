package chat

import (
	"database/sql"
	"log"
	"net"

	"github.com/rebeljah/gosqueak/services/message/database"
)

type user struct {
	uid  string
	sock *Socket
}

type Relay struct {
	db    *sql.DB
	users map[string]user
	recv  chan Message
}

func NewRelay(db *sql.DB) Relay {
	r := Relay{
		db:    db,
		users: make(map[string]user),
		recv:  make(chan Message, 0),
	}

	go r.recvLoop()
	return r
}
func (r Relay) AddUserConnection(uid string, conn net.Conn) {
	defer r.disconnect(uid)

	user := user{uid, NewSocket(conn)}
	r.users[uid] = user

	// usr sock will start putting events into the relay's recv channel
	user.sock.ChannelMessages(r.recv)
}
func (r Relay) recvLoop() {
	for msg := range r.recv {
		if user, ok := r.users[msg.ToUid]; ok { // user is connected
			go user.sock.WriteEvent(msg)
			continue
		}

		// user not connected, put in DB for recipient to get later
		go func(m Message){
			dbMsg := database.Message{ToUid: m.ToUid, Private: string(m.Private)}
			err := database.PostMessages(r.db, dbMsg)
			if err != nil {
				log.Println("Could not add message to database")
			}
		}(msg)
}	}
func (r Relay) disconnect(uid string) {
	user, ok := r.users[uid]

	if !ok {
		return
	}

	delete(r.users, uid)
	user.sock.Close()
}
