package socket

import (
	"encoding/json"
	"net"
)

type SockData struct {
	Map map[string]any
}

func Data() SockData {
	return SockData{make(map[string]any)}
}

func (s SockData) GetStr(key string) (string, bool) {
	val, ok := s.Map[key]
	if !ok {
		return "", false
	}

	str, ok := val.(string)
	return str, ok
}

func (s SockData) Set(key string, val any) SockData {
	s.Map[key] = val
	return s
}

type Message struct {
	Event uint8    `json:"e"`
	Data  SockData `json:"d"`
}

type Socket struct {
	Conn    net.Conn
	Muxes   map[string]*Mux
	encoder *json.Encoder
	decoder *json.Decoder
}

func NewSocket(c net.Conn) Socket {
	return Socket{
		Conn:    c,
		Muxes:   make(map[string]*Mux),
		encoder: json.NewEncoder(c),
		decoder: json.NewDecoder(c),
	}
}

func (s Socket) Emit(event uint8, data SockData) error {
	return s.WriteMessage(Message{Event: event, Data: data})
}

func (s Socket) ReadMessage() (Message, error) {
	var msg Message
	return msg, s.decoder.Decode(&msg)
}

func (s Socket) WriteMessage(m Message) error {
	return s.encoder.Encode(m)
}

func (s *Socket) HandleMessages() error {
	for {
		msg, err := s.ReadMessage()
		if err != nil {
			return err
		}

		for _, mux := range s.Muxes {
			go mux.HandleMessage(msg, s)
		}
	}
}

func (s *Socket) AddMux(name string, m *Mux) {
	s.Muxes[name] = m
}

func (s *Socket) DelMux(name string) {
	delete(s.Muxes, name)
}
func (s Socket) Close() {
	s.Conn.Close()
}
