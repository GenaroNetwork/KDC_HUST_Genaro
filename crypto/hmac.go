// We adopt HMAC-SHA256 as our pseudo-random function used in searchable encryption scheme

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMAC-SHA256
const HMACSize = 32 //bytes

// HMAC uses sha256 as hash function and outputs 32-byte mac
func HMAC(msg, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// CheckMAC reports whether msgMAC is a valid HMAC tag for message.
func CheckMAC(msg, msgMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(msgMAC, expectedMAC)
}