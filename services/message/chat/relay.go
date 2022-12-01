package chat

import (
	"net"
)

type user struct {
	uid  string
	sock *Socket
}

type Relay struct {
	users map[string]user
	recv  chan Message
	send  chan Message
}

func NewRelay() Relay {
	r := Relay{
		users: make(map[string]user),
		recv:  make(chan Message, 0),
		send:  make(chan Message, 0),
	}

	go r.sendLoop()
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
	for message := range r.recv {
		go r.handle(message)
	}
}
func (r Relay) sendLoop() {
	for message := range r.send {
		user, ok := r.users[message.ToUid]

		if !ok {
			continue // user not in relay
		}

		go user.sock.WriteEvent(message)
	}
}
func (r Relay) handle(message Message) {

}
func (r Relay) disconnect(uid string) {
	user, ok := r.users[uid]

	if !ok {
		return
	}

	delete(r.users, uid)
	user.sock.Close()
}
