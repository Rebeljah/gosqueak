package chat

import (
	"encoding/json"
	"net"

	"github.com/rebeljah/gosqueak/services/message/database"
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

func NewSocket(c net.Conn, enc *json.Encoder, dec *json.Decoder) *Socket {
	return &Socket{
		Conn:    c,
		encoder: enc,
		decoder: dec,
	}
}
func (s *Socket) ReadMessage() (m database.Message, err error) {
	err = s.decoder.Decode(&m)
	return
}
func (s *Socket) WriteMessage(m database.Message) error {
	return s.encoder.Encode(m)
}
func (s *Socket) ChannelMessages(ln chan<- database.Message) {
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
