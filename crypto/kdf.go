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

// GetSalt returns a salt value
func GetSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// KeyGen returns a master key
func KeyGen() ([]byte, error) {
	msk := make([]byte, MskLen)
	if _, err := io.ReadFull(rand.Reader, msk); err != nil {
		return nil, err
	}
	return msk, nil
}

// KeyDerivFunc generates sub key according to master key and salt
func KeyDerivFunc(msk, salt []byte, len int) []byte {
	return pbkdf2.Key(msk, salt, Iter, len, sha256.New)
}