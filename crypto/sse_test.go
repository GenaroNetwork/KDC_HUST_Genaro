package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

// Test padding
func TestPadding(t *testing.T) {
	keyword := []byte{0x11}
	result := SPadding(keyword)
	fmt.Println(keyword, len(result), result)

	k1 := SHA3_512(keyword)
	fmt.Println(k1)
	r1 := SPadding(k1)
	fmt.Println(len(r1), r1)

	k2 := []byte("Genaro Network is the first Turing Complete Public Chain with Decentralized Storage Network, " +
		"providing blockchain developers a one-stop solution to deploy smart contracts and store data simultaneously. " +
		"Meanwhile, Genaro provides everyone with a trustworthy internet and a sharing community. As the creator behind the " +
		"blockchain 3.0 concept, Genaro aims to contribute to blockchain infrastructure technology development. Through the Genaro Hub " +
		"and Accelerator, we aim to foster thousands of DAPPS, to move applications from Cloud to Blockchain and thereby create a global blockchain ecosystem")
	r2 := SPadding(k2)
	fmt.Println(SHA3_512(k2))
	fmt.Println(len(r2), r2)
}

// Test the encryption and decryption of AES-EBC
func TestAESECB(t *testing.T) {
	msk := KeyGen()

	salt := SaltGen()
	key := KeyDerivFunc(msk, salt, EKeyLen)

	plaintext := []byte("GenaroNetwork")
	plain := SPadding(plaintext)

	cipher, err := AESEncryptECB(key, plain)
	if err != nil {
		panic(err)
	}

	p, err := AESDecryptECB(key, cipher)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(plain, p) {
		fmt.Println("This test failed!")
	}
}

// Test symmetric searchable encryption scheme
func TestSearchEncryption(t *testing.T) {
	msk := KeyGen()

	salt := SaltGen()
	skey := KeyDerivFunc(msk, salt, SKeyLen)

	keyword := []byte("GenaroNetwork")
	scipher, err := SearchableEnc(keyword, skey)
	if err != nil {
		panic(err)
	}

	token, err := Trapdoor(keyword, skey)
	if err != nil {
		panic(err)
	}

	if !Matching(token, scipher) {
		fmt.Println("This test failed!")
	}
}
