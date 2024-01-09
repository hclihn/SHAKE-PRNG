package main

import (
	"fmt"
)

// For some reason, Run doesn't work. Use `go run  .` instead.
func main() {
  seed := []byte("test this out! you need to have enough inputs in the seed!")
  drbg, err := NewShakeDRBG(256, seed)
  if err != nil {
    fmt.Printf("ERROR: failed to create SHAKE DRBG: %+v\n", err)
    return
  }
  buf := make([]byte, 150)
  for i := 0; i < 3; i++ {
    if err := drbg.Generate(buf, []byte("test me!")); err != nil {
      fmt.Printf("ERROR: failed to generate SHAKE PRNG: %+v\n", err)
      return
    }
  	fmt.Printf("PRNG #%d: %#x\n", i, buf)
  }
}
