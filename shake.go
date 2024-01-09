package main

import (
	"encoding/binary"
	"io"
  "fmt"
)

// ShakeHash defines the interface to hash functions that
// support arbitrary-length output.
type ShakeHash interface {
	// Write absorbs more data into the hash's state. It panics if input is
	// written to it after output has been read from it.
	io.Writer

	// Read reads more output from the hash; reading affects the hash's
	// state. (ShakeHash.Read is thus very different from Hash.Sum)
	// It never returns an error.
	io.Reader

	// Clone returns a copy of the ShakeHash in its current state.
	Clone() ShakeHash

	// Reset resets the ShakeHash to its initial state.
	Reset()
}

// cSHAKE specific context
type cshakeState struct {
	*state // SHA-3 state context and Read/Write operations

	// initBlock is the cSHAKE specific initialization set of bytes. It is initialized
	// by newCShake function and stores concatenation of N followed by S, encoded
	// by the method specified in 3.3 of [1].
	// It is stored here in order for Reset() to be able to put context into
	// initial state.
	initBlock []byte
}

// Consts for configuring initial SHA-3 state
const (
	dsbyteShake  = 0x1f
	dsbyteCShake = 0x04
	rate128      = 168
	rate256      = 136
)

func bytepad(input []byte, w int) []byte {
	// leftEncode always returns max 9 bytes
	buf := make([]byte, 0, 9+len(input)+w)
	buf = append(buf, leftEncode(uint64(w))...)
	buf = append(buf, input...)
	padlen := w - (len(buf) % w)
	return append(buf, make([]byte, padlen)...)
}

func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)
	// Trim all but last leading zero bytes
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}
	// Prepend number of encoded bytes
	b[i-1] = 9 - i
	return b[i-1:]
}

func newCShake(N, S []byte, rate int, dsbyte byte) ShakeHash {
	c := cshakeState{state: &state{rate: rate, dsbyte: dsbyte}}

	// leftEncode returns max 9 bytes
	c.initBlock = make([]byte, 0, 9*2+len(N)+len(S))
	c.initBlock = append(c.initBlock, leftEncode(uint64(len(N)*8))...)
	c.initBlock = append(c.initBlock, N...)
	c.initBlock = append(c.initBlock, leftEncode(uint64(len(S)*8))...)
	c.initBlock = append(c.initBlock, S...)
	c.Write(bytepad(c.initBlock, c.rate))
	return &c
}

// Reset resets the hash to initial state.
func (c *cshakeState) Reset() {
	c.state.Reset()
	c.Write(bytepad(c.initBlock, c.rate))
}

// Clone returns copy of a cSHAKE context within its current state.
func (c *cshakeState) Clone() ShakeHash {
	b := make([]byte, len(c.initBlock))
	copy(b, c.initBlock)
	return &cshakeState{state: c.clone(), initBlock: b}
}

// Clone returns copy of SHAKE context within its current state.
func (c *state) Clone() ShakeHash {
	return c.clone()
}

// NewShake128 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() ShakeHash {
	return &state{rate: rate128, dsbyte: dsbyteShake}
}

// NewShake256 creates a new SHAKE256 variable-output-length ShakeHash.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() ShakeHash {
	return &state{rate: rate256, dsbyte: dsbyteShake}
}

func xorIn(d *state, buf []byte) {
  fmt.Printf("XorIn buf (%d): %#x\n", len(buf), buf)
	n := len(buf) / 8

	for i := 0; i < n; i++ {
		a := binary.LittleEndian.Uint64(buf)
		d.a[i] ^= a
		buf = buf[8:]
	}
}

func copyOut(d *state, b []byte) {
	for i := 0; len(b) >= 8; i++ {
		binary.LittleEndian.PutUint64(b, d.a[i])
		b = b[8:]
	}
}