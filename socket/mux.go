package socket

type HandlerFunc = func(SockData, *Socket)

type Mux struct {
	eventToFunc map[uint8]HandlerFunc
}

func NewMux() Mux {
	return Mux{eventToFunc: make(map[uint8]HandlerFunc)}
}

func (m *Mux) On(event uint8, f HandlerFunc) {
	m.eventToFunc[event] = f
}

func (m *Mux) HandleMessage(msg Message, sock *Socket) {
	if fun, ok := m.eventToFunc[msg.Event]; ok {
		fun(msg.Data, sock)
	}
}
