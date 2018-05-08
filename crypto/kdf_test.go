package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Test KDF functions
func TestKDF(t *testing.T) {
	salt, err := SaltGen()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(salt), salt)

	msk, err := KeyGen()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(msk), msk)

	sk := KeyDerivFunc(msk, salt)
	fmt.Println(len(sk), sk)
}

// Benchmark the generation of salt
func BenchmarkGetSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := SaltGen(); err != nil {
			panic(err)
			b.FailNow()
		}
	}
}

// Benchmark the generation of master key
func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := KeyGen(); err != nil {
			panic(err)
			b.FailNow()
		}
	}
}

// Benchmark the generation of sun key
func BenchmarkKeyDerivFunc(b *testing.B) {
	salt, err := SaltGen()
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}

	msk, err := KeyGen()
	if err != nil {
		panic(err)
		b.FailNow()
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = KeyDerivFunc(msk, salt)
	}
}

func TestKeyDerivFunce(t *testing.T) {
	salt, err := SaltGen()
	if err != nil {
		panic(err)
	}

	msk, err := KeyGen()
	if err != nil {
		panic(err)
	}

	for i := 0; i < 5; i++ {
		sub := KeyDerivFunc(msk, salt)
		fmt.Println(hex.EncodeToString(sub))
	}
}
