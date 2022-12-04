package chat_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rebeljah/gosqueak/services/message/chat"
	"github.com/rebeljah/gosqueak/services/message/database"
)

var sock *chat.Socket
var msg = database.Message{ToUid: "uid1", Private: "shhhh", KeyId: "key1"}

func TestReadMessage(t *testing.T) {
	expected := msg

	b, _ := json.Marshal(expected)
	sock = chat.NewSocket(nil, nil, json.NewDecoder(bytes.NewReader(b)))

	result, err := sock.ReadMessage()
	if err != nil {
		t.Fatalf(err.Error())
	}

	if result != expected {
		t.Fatal("result != expected")
	}
}

func TestWriteMessage(t *testing.T) {
	expected := msg
	var result database.Message

	b, _ := json.Marshal(expected)
	buf := bytes.NewBuffer(b)
	sock := chat.NewSocket(nil, json.NewEncoder(buf), nil)

	err := sock.WriteMessage(expected)
	if err != nil {
		t.Fatalf(err.Error())
	}

	err = json.NewDecoder(buf).Decode(&result)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if result != expected {
		t.Fatalf("result != expected")
	}
}

func TestChannelMessages(t *testing.T) {
	c := make(chan database.Message, 0)

	msg2 := msg
	msg.Private = "Quiet!"

	buf := make([]byte, 0)
	for _, m := range []database.Message{
		msg,
		msg2,
	} {
		b, _ := json.Marshal(m)
		buf = append(buf, b...)
	}

	r := bytes.NewReader(buf)
	dec := json.NewDecoder(r)
	sock := chat.NewSocket(nil, nil, dec)

	go sock.ChannelMessages(c)

	var i int
	for i = 0; i < 2; i++ {
		m := <- c
		if m != msg && m != msg2 {
			t.Fatalf("invalid message")
		}
	}
}
