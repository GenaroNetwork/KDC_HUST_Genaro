// This is a symmetric cryptosystem including Hash functions and symmetric encryption-decryption algorithm
// SHA1 is only used in the generation of fileid. We use SHA3-256 and SHA3-512 as our secure one-way hash functions
// SHA-3 is the latest member of the Secure Hash Algorithm family of standards, released by NIST on August 5, 2015

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"io"
)

var (
	// The length of symmetric encryption key
	EKeyLen = 32
)

// SHA1 returns the SHA1 hash of the input data
func SHA1(data []byte) (digest [sha1.Size]byte) {
	h := sha1.New()
	h.Write(data)
	h.Sum(digest[:0])
	return
}

// SHA3_256 returns the SHA3-256 hash of the input data
func SHA3_256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// SHA3_512 returns the SHA3-256 hash of the input data
func SHA3_512(data ...[]byte) []byte {
	d := sha3.NewKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// getIV returns an initialisation vector for OFB mode.
func getIV(blockSize int) ([]byte, error) {
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// AESEncryptOFB generates an AES ciphertext using OFB pattern
func AESEncryptOFB(key, plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv, err := getIV(block.BlockSize())
	if err != nil {
		return nil, errors.New("AESEncryptCFB: failed to generate IV")
	}

	ciphertext = make([]byte, block.BlockSize()+len(plaintext))
	copy(ciphertext, iv)

	cfb := cipher.NewOFB(block, iv)
	cfb.XORKeyStream(ciphertext[block.BlockSize():], plaintext)
	return
}

// AESDecryptOFB returns a plaintext
func AESDecryptOFB(key, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = make([]byte, len(ciphertext)-block.BlockSize())

	cfb := cipher.NewOFB(block, ciphertext[:block.BlockSize()])
	cfb.XORKeyStream(plaintext, ciphertext[block.BlockSize():])
	return
}
