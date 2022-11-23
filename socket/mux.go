package socket

type HandlerFunc = func(SockData, *Socket)

// event enum
const (
	EventRegisterUser = iota
	EventGrantedJWT
	EventJWTLogin
	EventPasswordLogin
)

type Mux struct {
	eventToFunc map[uint8]HandlerFunc
}

func NewMux() Mux {
	return Mux{eventToFunc: make(map[uint8]HandlerFunc)}
}

func (self *Mux) On(event uint8, f HandlerFunc) {
	self.eventToFunc[event] = f
}

func (self *Mux) HandleMessage(msg Message, sock *Socket) {
	if fun, ok := self.eventToFunc[msg.Event]; ok {
		fun(msg.Data, sock)
	}
}
