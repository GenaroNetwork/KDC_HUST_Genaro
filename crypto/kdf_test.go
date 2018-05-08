package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Test KDF functions
func TestKDF(t *testing.T) {
	salt := SaltGen()
	fmt.Println(len(salt), salt)

	msk := KeyGen()
	fmt.Println(len(msk), msk)

	sk := KeyDerivFunc(msk, salt, 32)
	fmt.Println(len(sk), sk)
}

// Benchmark the generation of salt
func BenchmarkGetSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SaltGen()
	}
}

// Benchmark the generation of master key
func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		KeyGen()
	}
}

// Benchmark the generation of sub key
func BenchmarkKeyDerivFunc(b *testing.B) {
	salt := SaltGen()

	msk := KeyGen()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = KeyDerivFunc(msk, salt, 32)
	}
}

func TestKeyDerivFunce(t *testing.T) {
	salt := SaltGen()

	msk := KeyGen()

	for i := 0; i < 5; i++ {
		sub := KeyDerivFunc(msk, salt, 32)
		fmt.Println(hex.EncodeToString(sub))
	}
}
