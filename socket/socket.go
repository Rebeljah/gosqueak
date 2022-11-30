package socket

import (
	"encoding/json"
	"net"
)

type Data map[string]any

func (s Data) GetStr(key string) string {
	val, _ := s[key].(string)
	return val
}
func (s Data) Set(key string, val any) Data {
	s[key] = val
	return s
}

type Event struct {
	OpCode uint8  `json:"e"`
	Data   Data   `json:"d"`
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
func (s *Socket) ReadEvent() (e Event, err error) {
	s.decoder.Decode(&e)
	return
}
func (s *Socket) WriteEvent(e Event) error {
	return s.encoder.Encode(e)
}
func (s *Socket) Listen(ln chan<- Event) {
	for {
		e, err := s.ReadEvent()

		if err != nil {
			return
		}

		ln <- e
	}
}
func (s *Socket) Close() {
	s.Conn.Close()
}
