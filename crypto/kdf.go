// We use PBKDF2 as our key derivation functions used in kdc
// According to NIST 800-63, the length of salt is at least 4-byte
// and at least 10,000 iterations are needed

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

const (
	// iterations of pbkdf2 algorithm
	Iter = 10000

	// salt size
	SaltLen = 10

	// mater key size
	MskLen = 16
)

func randomBytes(size uint32) []byte {
	bytes := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		panic(err)
	}
	return bytes
}

// SaltGen returns a salt value
func SaltGen() []byte {
	return randomBytes(SaltLen)
}

// KeyGen returns a master key
func KeyGen() []byte {
	return randomBytes(MskLen)
}

// KeyDerivFunc generates sub key according to master key and salt
func KeyDerivFunc(msk, salt []byte, len int) []byte {
	return pbkdf2.Key(msk, salt, Iter, len, sha256.New)
}
