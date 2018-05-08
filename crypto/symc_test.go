package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSHA1(t *testing.T) {
	msg := "Genaro Network"
	msghash := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

	h := SHA1([]byte(msg))
	result := hex.EncodeToString(h[:])

	if result != msghash {
		fmt.Println("This test failed!")
	}

}

func TestSHA3_256(t *testing.T) {
	msg := "Genaro Network"
	msghash := "0f1fb36a52726c037b3a7a5cd6be1658824b6ecaa1397463b9100b9930dba40b"

	h := SHA3_256([]byte(msg))
	result := hex.EncodeToString(h[:])

	if result != msghash {
		fmt.Println("This test failed!")
	}
}

func TestSHA3_512(t *testing.T) {
	msg := "Genaro Network"
	msghash := "77bc16b507883543344a84690de7cd6177b31a2cf24f6db3e18b62c3b83cf25d" +
		"ff2aa451c8140cdcece523bacda6825cb7554fd9dcbef06f4d57c5ad289f7c93"

	h := SHA3_512([]byte(msg))
	result := hex.EncodeToString(h[:])

	if result != msghash {
		fmt.Println("This test failed!")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	msk := KeyGen()

	salt := SaltGen()
	key := KeyDerivFunc(msk, salt, EKeyLen)

	msg := []byte("Genaro Network")
	fmt.Println(len(msg))

	ciphertext, err := AESEncryptOFB(key, msg)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(ciphertext))

	plaintext, err := AESDecryptOFB(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(plaintext))

	if !bytes.Equal(msg, plaintext) {
		fmt.Println("This test failed!")
	}
}
