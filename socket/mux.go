package socket

type HandlerFunc = func(Event)

type Mux struct {
	eventToFunc map[uint8]HandlerFunc
}

func NewMux() *Mux {
	return &Mux{eventToFunc: make(map[uint8]HandlerFunc)}
}

func (m Mux) On(event uint8, f HandlerFunc) {
	m.eventToFunc[event] = f
}

func (m Mux) HandleMessage(msg Event) {
	if fun, ok := m.eventToFunc[msg.OpCode]; ok {
		fun(msg)
	}
}
