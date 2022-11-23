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

func (self SockData) GetStr(key string) (string, bool) {
	val, ok := self.Map[key]
	if !ok {
		return "", false
	}

	str, ok := val.(string)
	return str, ok
}

func (self SockData) Set(key string, val any) SockData {
	self.Map[key] = val
	return self
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

func (self Socket) Emit(event uint8, data SockData) error {
	return self.WriteMessage(Message{Event: event, Data: data})
}

func (self Socket) ReadMessage() (Message, error) {
	var msg Message
	return msg, self.decoder.Decode(&msg)
}

func (self Socket) WriteMessage(m Message) error {
	return self.encoder.Encode(m)
}

func (self *Socket) HandleMessages() error {
	for {
		msg, err := self.ReadMessage()
		if err != nil {
			return err
		}

		for _, mux := range self.Muxes {
			go mux.HandleMessage(msg, self)
		}
	}
}

func (self *Socket) AddMux(name string, m *Mux) {
	self.Muxes[name] = m
}

func (self *Socket) DelMux(name string) {
	delete(self.Muxes, name)
}
func (self Socket) Close() {
	self.Conn.Close()
}
