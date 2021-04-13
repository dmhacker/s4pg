package s4pg

import (
	"math/rand"
)

func Shred(sensitive []byte) {
	for i := 0; i < 5; i++ {
		rand.Read(sensitive)
        for j := range sensitive {
            sensitive[j] = byte(i)
        }
	}
}
