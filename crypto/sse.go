// This Searchable Symmetric Encryption Scheme (SSE) is from a paper proposed by Song et al. in IEEE S&P 2000.
// Citation: Dawn Xiaoding Song, D. Wagner and A. Perrig, "Practical techniques for searches on encrypted data,"
// Proceeding 2000 IEEE Symposium on Security and Privacy. S&P 2000, Berkeley, CA, 2000, pp. 44-55.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// The length of searchable ciphertext
	SSize = 64

	// The length of searchable encryption key
	SKeyLen = 32

	// The length of the right part of search token
	Rtoken = 16
)

// SPadding pads the keyword as long as a searchable ciphertext
// The padded keyword cannot be restored
func SPadding(keyword []byte) []byte {
	if len(keyword) == SSize {
		return keyword
	}
	// if SSize != 64, the hash function needs to be changed
	if len(keyword) > SSize {
		return SHA3_512(keyword)
	}
	paddingCount := SSize - len(keyword)
	return append(keyword, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
}

// XORBytes computes the XOR of two byte slices
func XORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// AESEncryptECB is a deterministic encryption algorithm used in SSE sechme
func AESEncryptECB(key, plaintext []byte) (cipher []byte, err error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("AESEncryptECB: plaintext size error")

	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher = make([]byte, len(plaintext))
	bcipher := make([]byte, aes.BlockSize)

	// encrypt plaintext by block
	for index := 0; index < len(plaintext); index += aes.BlockSize {
		block.Encrypt(bcipher, plaintext[index:index+aes.BlockSize])
		copy(cipher[index:index+aes.BlockSize], bcipher)
	}
	return cipher, nil

}

// AESDecryptECB returns the plaintext of the input cipher
func AESDecryptECB(key, cipher []byte) (plaintext []byte, err error) {
	if len(cipher)%aes.BlockSize != 0 {
		return nil, errors.New("AESDecryptECB: cipher size error")

	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = make([]byte, len(cipher))
	bplain := make([]byte, aes.BlockSize)

	// decrypt plaintext by block
	for index := 0; index < len(cipher); index += aes.BlockSize {
		block.Decrypt(bplain, cipher[index:index+aes.BlockSize])
		copy(plaintext[index:index+aes.BlockSize], bplain)
	}
	return plaintext, nil

}

// GetRandom returns a random stream
func GetRandom(len int) ([]byte, error) {
	random := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, err
	}
	return random, nil
}

// SearchableEnc generates a searchable ciphertext for the keyword
func SearchableEnc(keyword, skey []byte) (scipher []byte, err error) {
	word := SPadding(keyword)
	key1 := skey[:SKeyLen/2]
	key2 := skey[SKeyLen/2:]

	// generate deterministic ciphertext
	dc, err := AESEncryptECB(key1, word)
	if err != nil {
		return nil, fmt.Errorf("SearchableEnc: failed to encrypt keyword with error: %s", err.Error())
	}

	// generate key3
	key3 := KeyDerivFunc(key2, dc, Rtoken)

	// generate random stream
	rlen := SSize - HMACSize
	left, err := GetRandom(rlen)
	if err != nil {
		return nil, err
	}

	// generate stream ciphertext
	right := HMAC(left, key3)
	sc := make([]byte, SSize)
	copy(sc, left)
	copy(sc[rlen:], right)

	// generate searchable ciphertext
	scipher = make([]byte, SSize)
	XORBytes(scipher, dc, sc)
	return scipher, nil
}

// Trapdoor generates a keyword search token
func Trapdoor(keyword, skey []byte) (token []byte, err error) {
	word := SPadding(keyword)
	key1 := skey[:SKeyLen/2]
	key2 := skey[SKeyLen/2:]

	// generate left token
	ltoken := make([]byte, SSize)
	ltoken, err = AESEncryptECB(key1, word)
	if err != nil {
		return nil, fmt.Errorf("Trapdoor: failed to encrypt keyword with error: %s", err.Error())
	}

	// generate right token
	rtoken := KeyDerivFunc(key2, ltoken, Rtoken)

	// generate token
	token = make([]byte, SSize+Rtoken)
	copy(token, ltoken)
	copy(token[SSize:], rtoken)
	return token, nil
}

//  Matching judges whether the token and the cipher contain same keyword
func Matching(token, scipher []byte) bool {
	if len(scipher) != SSize {
		return false
	}

	sc := make([]byte, SSize)
	XORBytes(sc, scipher, token[:SSize])

	rlen := SSize - HMACSize
	return bytes.Equal(sc[rlen:], HMAC(sc[:rlen], token[SSize:]))
}
