package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"sync"
)

// CryptoSource implements rand.Source64 using AES-CTR to produce
// cryptographically secure pseudorandom numbers from a seed.
// This solves the entropy truncation issue of math/rand.
type CryptoSource struct {
	mu     sync.Mutex
	stream cipher.Stream
	// Buffer for the random bytes; 8 bytes needed for Uint64
	buf [8]byte
}

// NewCryptoSource creates a new source seeded with the provided bytes.
// The seed must be 32 bytes (256 bits) for AES-256.
func NewCryptoSource(seed []byte) (*CryptoSource, error) {
	if len(seed) != 32 {
		// Expand or truncate seed to 32 bytes if necessary,
		// but preferably the caller should provide 32 bytes.
		// For robustness, we can hash it or panic, but here we expect 32.
		return nil, aes.KeySizeError(len(seed))
	}

	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}

	// Use a zero IV for deterministic generation from the seed
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	return &CryptoSource{
		stream: stream,
	}, nil
}

// Seed is a no-op for CryptoSource as it is seeded at creation.
// This satisfies the rand.Source interface.
func (s *CryptoSource) Seed(seed int64) {
	// No-op: We don't want to reduce our 256-bit security to 63 bits.
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64.
func (s *CryptoSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

// Uint64 returns a pseudo-random 64-bit value as a uint64.
func (s *CryptoSource) Uint64() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate 8 bytes of randomness
	s.stream.XORKeyStream(s.buf[:], s.buf[:]) // XORing zero-buffer effectively reads the stream

	// We need to XOR input, but since we just want random bytes, we can encrypt a buffer of zeros.
	// Actually, cipher.Stream.XORKeyStream(dst, src). If src is zero, dst becomes the keystream.
	// But to be safe and clear:
	// We maintain internal state via the stream. We just need the next 8 bytes of keystream.
	// A common way with CTR is to encrypt a counter, but NewCTR does that for us.
	// We just need to supply *some* input. If we supply zeros, we get the raw keystream.
	// However, reusing the same buffer for src and dst is allowed.
	// We need to ensure s.buf is cleared or just use it?
	// Actually, XORKeyStream XORs src with the keystream.
	// If we want pure random bytes from the keystream, src MUST be 0.
	// So we reset buf to 0 before generation.
	s.buf[0] = 0
	s.buf[1] = 0
	s.buf[2] = 0
	s.buf[3] = 0
	s.buf[4] = 0
	s.buf[5] = 0
	s.buf[6] = 0
	s.buf[7] = 0

	s.stream.XORKeyStream(s.buf[:], s.buf[:])

	return binary.LittleEndian.Uint64(s.buf[:])
}
