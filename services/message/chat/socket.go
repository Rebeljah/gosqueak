package chat

import (
	"encoding/json"
	"net"
)

type Message struct {
	ToUid   string
	Private []byte
}

type Socket struct {
	Conn    net.Conn
	encoder *json.Encoder
	decoder *json.Decoder
}

func NewSocket(c net.Conn) *Socket {
	return &Socket{
		Conn:    c,
		encoder: json.NewEncoder(c),
		decoder: json.NewDecoder(c),
	}
}
func (s *Socket) ReadMessage() (m Message, err error) {
	s.decoder.Decode(&m)
	return
}
func (s *Socket) WriteEvent(m Message) error {
	return s.encoder.Encode(m)
}
func (s *Socket) ChannelMessages(ln chan<- Message) {
	for {
		message, err := s.ReadMessage()

		if err != nil {
			return
		}

		ln <- message
	}
}
func (s *Socket) Close() {
	s.Conn.Close()
}
