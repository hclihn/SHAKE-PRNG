package main

import (
  "errors"
  "fmt"
  "math/bits"
)

const (
	// MaxInputLength is the maximum length of the input data in bytes.
	MaxInputLength = 1 << 32 // 2^35 bits
	// ReseedInterval is the maximum number of requests that can be made before a reseed operation is required.
	ReseedInterval = 1 << 48
	// MaxBytesPerRequest is the maximum number of bytes allowed per request
	MaxBytesPerRequest = 1 << 16 // 2^19 bits.
	// RecommendedKMAC128KeyTagSize is the recommended KMAC128 key and tag size in bytes to provide the maximum
	// security strength
  RecommendedKMAC128KeyTagSize = 32
	// RecommendedKMAC256KeyTagSize is the recommended KMAC256 key and tag size in bytes to provide the maximum
	// security strength
	RecommendedKMAC256KeyTagSize = 64
  	// The following rates in bytes are specified by [1] (also serves as the block size).
  nClear = 25 // number of state bytes to clear (12.5% or 1/8 of 1600 bits)

)

var ErrDRBGReseed = errors.New("")

func WrapTraceableErrorf(err error, format string, args ...any) error {
  msg := fmt.Sprintf(format, args...)
  if err != nil {
    return fmt.Errorf("%s: %w", msg, err)
  }
  return fmt.Errorf("%s", msg)
}

// ShakePRNG is the SHAKE based pseudo random number generator
type ShakePRNG struct {
	// set the following at object creation
	c       ShakeHash // use SHAKExxx hash only!
	rate    int            // Keccak rate
	seedLen int            // recommended seed length
	// the following are operational variables (no initialization needed at creation)
	counter int // counter for reseed
  nw int
}

// gen10x01Pad generates the 10*01 padding for n bytes long
func (s ShakePRNG) gen10x01Pad(n int) []byte {
	const dsbyteShake = 0x1f // SHAKE domain-separator bits (0x0f) plus the first one bit for the 10*01 padding
	if n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	buf[0] = dsbyteShake
	buf[n-1] ^= 0x80 // the last one bit for the 10*01 padding
	return buf
}

// writeWithPad writes p into SHAKE hash c with 0 padding.
// p is pre-padded with s.nw counts of 0 bytes. It is then padded with 0 bytes up to the multiples of s.rate bytes.
// The padding forces the SHAKE hash to permute its states.
// s.nw is update.
func (s *ShakePRNG) writeWithPad(c ShakeHash, p []byte, start byte) error {
	if len(p) == 0 { // no-op
		return nil
	}
  offset := int(start)
  fmt.Printf("writeWithPad offset: %#x\n", offset)
	// use s.nw to create a pre-pad so that we won't always XOR the same starting place in SHAKE states
	buf := make([]byte, offset+len(p))
	copy(buf[offset:], p)
	if _, err := c.Write(buf); err != nil {
		c.Reset()
		return WrapTraceableErrorf(err, "failed to write pre-pad + data into DRBG hash")
	}
	// create a post-pad to force the SHAKE hash to perform Keccak permute on states
	nPad := s.rate - (len(buf) % s.rate) // len(buf) is s.nw + len(p)!
	if _, err := c.Write(make([]byte, nPad)); err != nil {
		c.Reset()
		return WrapTraceableErrorf(err, "failed to write post-pad into DRBG hash")
	}
  s.nw++
	return nil
}

func (s ShakePRNG) getStartFrom(buf []byte) byte {
	// We use the XOR of all bytes in buf (with a proper modulo) to set the starting index of states to be cleared.
	// In this way, we don't always start from the same place which is harder for the hacker to track.
	sum := byte(0)
	for _, x := range buf {
		sum ^= x
	}
	sum += byte(s.nw+1)
	r := s.nw
	if r & 0xa55a != 0 {
		r = -r
	}
	return bits.RotateLeft8(sum, r)
}

// createMask uses b to create the XOR masks in place.
// Instead of creating masks to clear some of the states, we will use bit rotation and XOR to create masks which will
// preserve the entropy of the states.
func (s *ShakePRNG) createMask(b []byte) {
	l := len(b)
	if l == 0 { // no-op
		return
	}
	tmp := make([]byte, l)
	// check if all b's are of the same value
	notAllSame, b0 := false, b[0]
	for i := 1; i < l; i++ {
		if b[i] != b0 {
			notAllSame = true
			break
		}
	}
	b0 = 0 // wipe it!
	for i := 0; i < l; i++ {
		if notAllSame {
			tmp[i] = b[i]
		} else { // very unlikely: all b's are the same, add the index to mutate them
			tmp[i] = b[i] + byte(i+1)
		}
	}
	// rotate bits and XOR
	for i := 0; i < l; i++ {
		sum := b[i]
		for j := 1; j < l; j++ {
			idx := (i + j) % l
			if r := j & 0x07; r == 0 { // flip it
				sum ^= (tmp[idx] ^ 0xff)
			} else {
				if j&0x0a != 0 { // change direction
					r = -r
				}
				sum ^= bits.RotateLeft8(tmp[idx], r)
			}
		}
		b[i] = sum
	}
}

// Generate generates a random bit stearm to fill []byte out.
// Optional (but recommended) additionalIn is used to help the generation and increase its resistance to hackers
// An error wrapping ErrDRBGReseed will be returned if the DRBG needs to be reseeded (use errors.Is to test)
// It's destroyed on error.
func (s *ShakePRNG) Generate(out, additionalIn []byte) error {
	if s.NeedReseed() {
		return WrapTraceableErrorf(ErrDRBGReseed, "exceeding reseed limit: reseed before generating PRNG")
	}
	lo, li := len(out), len(additionalIn)
	if lo > MaxInputLength { // In theory, this would be 2^(c/2) bits where c is capacity (1600 - rate) in bits.
		// However, 2^32 is big enough in practice. Yes, we are using MaxInputLength, instead of MaxBytesPerRequest
		// (2^16) which is a bit small.
		return WrapTraceableErrorf(nil, "output length (%d) too long: needs at most %d bytes", lo, MaxInputLength)
	} else if lo == 0 {
		return WrapTraceableErrorf(nil, "empty output specified")
	}
	if li > MaxInputLength {
		return WrapTraceableErrorf(nil, "additional input length (%d) too long: needs at most %d bytes",
			li, MaxInputLength)
	}
  fmt.Printf("* Generate additionalIn write...\n")
	if err := s.writeWithPad(s.c, additionalIn, s.getStartFrom(additionalIn)); err != nil {
		s.Destroy()
		return WrapTraceableErrorf(err, "failed to write additional input into DRBG hash")
	}
	// create a cloned hash before Read() since SHAKE hash won't allow us to write after read.
	dup := s.c.Clone()
	// make sure buf's last chunk is always s.rate-1 bytes long
	// read s.rate-1 bytes so that it won't trigger Keccak permute on states
  fmt.Printf("* Generate Read...\n")
	buf := make([]byte, ((lo/s.rate)+1)*s.rate - 1)
	if _, err := s.c.Read(buf); err != nil {
		s.Destroy()
		return WrapTraceableErrorf(err, "failed to generate PRNG from DRBG hash")
	}
	copy(out, buf)
	// simulate read on dup
	// First, from write (absorb) to read (squeeze), SHAKE hash generates a 10*01 pad
  fmt.Printf("* Generate dup write 10*01 pad...\n")
	if _, err := dup.Write(s.gen10x01Pad(s.rate)); err != nil {
		s.Destroy()
		dup.Reset()
		return WrapTraceableErrorf(err, "failed to write 10*01 pad into DRBG hash")
	}
	nr := len(buf)
	// For every s.rate bytes read, there is a Keccak permute on states. Writing 0-pad can achieve this effect.
	nq := nr / s.rate
	cBuf := make([]byte, s.rate) // 0 pads
	for ; nq > 0; nq-- {
    fmt.Printf("* generate dup simulate-read write...\n")
		if _, err := dup.Write(cBuf); err != nil {
			s.Destroy()
			dup.Reset()
			return WrapTraceableErrorf(err, "failed to write 0 pad into DRBG hash")
		}
	}
	// Clear nClear bytes of states. Since we use XOR and rotate on output bytes, we preserve the entropy of the data.
	// This is better than clearing states into all 0s or 1s which removes the entropy.
	start := int(s.getStartFrom(buf)) % (s.rate - nClear - 1) // within the last chunk of s.rate-1 bytes
	offset := nq*s.rate + start                     // within buf
	b := buf[offset : offset+nClear]
  fmt.Printf("** start: %#x (%#x), b: %#x\n", 
      start, offset, b)
	s.createMask(b)
  fmt.Printf("** mask: %#x\n", b)
  fmt.Printf("* Generate state clear write...\n")
	if err := s.writeWithPad(dup, b, byte(start)); err != nil {
		s.Destroy()
		return WrapTraceableErrorf(err, "failed to write masks into DRBG hash")
	}
	s.c.Reset()
	s.c = dup
	s.counter++
	return nil
}

// Reseed reseeds the DRBG with seed
// It's destroyed on error.
func (s *ShakePRNG) Reseed(seed []byte) error {
	minLen := s.seedLen / 2
	l := len(seed)
	if l < minLen {
		return WrapTraceableErrorf(nil, "seed length (%d) too short: needs at least %d bytes", l, minLen)
	}
	if l > MaxInputLength {
		return WrapTraceableErrorf(nil, "seed length (%d) too long: needs at most %d bytes", l, MaxInputLength)
	}
  fmt.Printf("* Seed write...\n")
	if err := s.writeWithPad(s.c, seed, s.getStartFrom(seed)); err != nil {
		s.Destroy()
		return WrapTraceableErrorf(err, "failed to write seed into DRBG hash")
	}
	s.counter = 0
	return nil
}

// NeedReseed indicates if the DRBG needs to be reseeded
func (s ShakePRNG) NeedReseed() bool {
	// In theory, this should be r*2^(r/2) bits where r is the rate (in bits). However, 2^48 (defined by NIST for DRBG)
	// is big enough in practice.
	return s.counter > ReseedInterval
}

// Reset resets the states of the DRBG and starts it with seed
// It's destroyed on error.
func (s *ShakePRNG) Reset(seed []byte) error {
	s.c.Reset()
  s.nw = 0
	return s.Reseed(seed)
}

// Destroy clears DRBG's internal states. It's not usable afterwards.
func (s *ShakePRNG) Destroy() {
	s.c.Reset()
	s.c = nil
	s.rate, s.seedLen, s.counter, s.nw = 0, 0, 0, 0
}

// NewShakeDRBG returns a new KMAC hash DRBG with seed
// Per the NIST std, seed is the concatenated bytes of entropy_input, nonce, and personalized_string.
func NewShakeDRBG(bits int, seed []byte) (*ShakePRNG, error) {
	var drbg ShakePRNG
	switch bits {
	case 128:
		drbg.seedLen = RecommendedKMAC128KeyTagSize
		drbg.c = NewShake128()
		drbg.rate = rate128
	case 256:
		drbg.seedLen = RecommendedKMAC256KeyTagSize
		drbg.c = NewShake256()
		drbg.rate = rate256
	default:
		return nil, WrapTraceableErrorf(nil, "unsupported size (%d) for SHAKE DRBG", bits)
	}
	// initialize it
	if err := drbg.Reset(seed); err != nil {
		return nil, WrapTraceableErrorf(err, "failed to initialize the SHAKE%d DRBG", bits)
	}
	return &drbg, nil
}
