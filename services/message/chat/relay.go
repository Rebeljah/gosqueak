package chat

import (
	"net"

	"github.com/rebeljah/gosqueak/socket"
)

type user struct {
	uid  string
	sock *socket.Socket
}

type Relay struct {
	users         map[string]user
	mux           *socket.Mux
	InboundEvents chan socket.Event
}
func NewRelay() Relay {
	r := Relay{
		users:         make(map[string]user),
		mux:           socket.NewMux(),
		InboundEvents: make(chan socket.Event, 256),
	}

	go r.handleIncomingEvents()
	return r
}
func (r Relay) HandleUserConnection(uid string, conn net.Conn) {
	r.users[uid] = user{uid, socket.NewSocket(conn)}
	go r.listenToUser(r.users[uid])
}
func (r Relay) listenToUser(u user) {
	defer r.disconnectUser(u.uid)
	// block and start receiving events
	u.sock.Listen(r.InboundEvents)
}
func (r Relay) disconnectUser(uid string) {
	defer delete(r.users, uid)
	r.users[uid].sock.Close()
}
func (r Relay) handleIncomingEvents() {
	for e := range r.InboundEvents {
		r.mux.HandleMessage(e)
	}
}


