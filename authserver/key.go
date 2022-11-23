package authserver

import (
	"os"

	"golang.org/x/exp/slices"
)

// var keyReadMutex sync.Mutex
var cachedKey []byte

func getKey() []byte {
	// keyReadMutex.Lock()
	// defer keyReadMutex.Unlock()

	if len(cachedKey) > 0 {
		return slices.Clone(cachedKey)
	}

	f, err := os.Open("./server/auth/key")
	if err != nil {
		panic(err)
	}

	cachedKey = make([]byte, 512)
	if n, err := f.Read(cachedKey); err != nil || n != 512 {
		panic(err)
	}

	return cachedKey
}
