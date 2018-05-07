package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

var key = []byte("key for HMAC testing")

var msg = []string{
	"00000000000",
	"Genaro",
	"Genaro Network – Revolution of Blockchain 3.0",
	"Genaro Network is the first Turing Complete Public Chain with Decentralized Storage Network, " +
		"providing blockchain developers a one-stop solution to deploy smart contracts and store data simultaneously. " +
		"Meanwhile, Genaro provides everyone with a trustworthy internet and a sharing community. As the creator behind the " +
		"blockchain 3.0 concept, Genaro aims to contribute to blockchain infrastructure technology development. Through the Genaro Hub " +
		"and Accelerator, we aim to foster thousands of DAPPS, to move applications from Cloud to Blockchain and thereby create a global blockchain ecosystem",
}

var msghash = []string{
	"673d12f6a2729a38106817dcd5f634c3a0770c93fab9b9c97e6e6effbcc6af40",
	"ae4e6698a47c9922b7149348c118fa1d89b8f4c5fabe2ba0589dc75bf1198773",
	"2cee7b8879434c9b4f74778b49f148fd6dbf0523190fca80d75cb97a6b09563a",
	"b728c8ec22139dffe16f003fef9d0e572828515acd99c1f23cfba963d0929b20",
}

func TestGeneratHMAC(t *testing.T) {
	for _, m := range msg {
		h := HMAC([]byte(m), key)
		result := hex.EncodeToString(h)
		fmt.Println(len(h), result)
	}
}

func TestHMAC(t *testing.T) {
	for i, m := range msg {
		h := HMAC([]byte(m), key)
		expectedMAC, _ := hex.DecodeString(msghash[i])
		if !bytes.Equal(h, expectedMAC) {
			t.Errorf("Hash not equal to expected output.\n")
		}
	}
}

func TestCheckMAC(t *testing.T) {
	for i, h := range msghash {
		expectedMAC, _ := hex.DecodeString(h)
		b := CheckMAC([]byte(msg[i]), expectedMAC, key)
		if !b {
			t.Errorf("CheckMAC returned false.\n")
		}
	}
}
