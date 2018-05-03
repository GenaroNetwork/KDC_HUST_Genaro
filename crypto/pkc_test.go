package crypto

import (

	"fmt"
	"testing"
	"crypto/rand"
	"bytes"
	"encoding/hex"
)

var
(
	ecieskeypath = "eciestest"
	message      = []byte("Genaro Network")
	testcipher   = "048931adf3310ee06db7e5c37179ad905891b54dd568af058a1273f7d875d5298b7059efb8ab631a5e1d15a031c26" +
		"90d3c8a74febb6c7b3e300d8c8b6179c9d0360ac48dc793748f52af4468f6eeca549ce901beef58b87bd0adfe3a08" +
		"d29035a31bbb62ad0726aed10ddd7f19fe625148c8b051b3e5d518fb73acbeff3bf0"
)

func TestEciesEncryptDecrypt(t *testing.T) {
	// load ecies key
	pri, err := LoadEciesKeyFromFile(ecieskeypath)
	if err != nil {
		panic(err)
	}

	// encrypt message
	ct, err := EciesEncrypt(rand.Reader, &pri.PublicKey, message)
	if err != nil {
		panic(err)
	}

	// decrypt newly generated cipher
	pt, err := EciesDecrypt(rand.Reader, ct, pri)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(message, pt) {
		fmt.Println("This test failed!")
	}

	// decrypt testcipher
	ct1, err := hex.DecodeString(testcipher)
	if err != nil {
		panic(err)
	}
	pt1, err := EciesDecrypt(rand.Reader, ct1, pri)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(message, pt1) {
		fmt.Println("This test failed!")
	}
}

func TestSignVerify(t *testing.T) {
	pri, err := GenerateEcdsaPri(rand.Reader, DefaultCurve)
	if err != nil {
		panic(err)
	}

	// sign message
	sign, err := SignMessage(message, pri)
	if err != nil {
		panic(err)
	}

	// verify signature
	if !VerifySignature(message, sign, &pri.PublicKey) {
		fmt.Println("This test failed!")
	}

	if !VerifySignNoPub(message, sign) {
		fmt.Println("This test failed!")
	}
}

// test transformation of key pairs
func TestTransformKey(t *testing.T) {
	// generate keys
	spri, _ := GenerateEcdsaPri(rand.Reader, DefaultCurve)
	epri, _ := GenerateEciesPri(rand.Reader, DefaultCurve)

	skp := new(KeyPairs)
	ekp := new(KeyPairs)

	// test transformation of ecdsa key pair
	skp.EcdsaKeyToBytes(spri, DefaultCurve)
	fmt.Println(skp.Pk, "\n", skp.Sk)
	p1, err := BytesToEcdsaKey(skp.Pk, skp.Sk, DefaultCurve)
	if err != nil {
		panic(err)
	}
	flag := cmpEcdsaPrivate(spri, p1)
	if flag == false {
		fmt.Println("ErrcmpEcdsaPrivate")
	}

	// test transformation of ecies key pair
	ekp.EciesKeyToBytes(epri, DefaultCurve)
	fmt.Println(ekp.Pk, "\n", ekp.Sk)
	p2, err:= BytesToEciesKey(ekp.Pk, ekp.Sk, DefaultCurve)
	if err != nil {
		panic(err)
	}
	flag = cmpEciesPrivate(epri, p2)
	if flag == false {
		fmt.Println("ErrcmpEciesPrivate")
	}

}

func TestSaveKey(t *testing.T) {
	spri, _ := GenerateEcdsaPri(rand.Reader, DefaultCurve)
	epri, _ := GenerateEciesPri(rand.Reader, DefaultCurve)

	skp := new(KeyPairs)
	ekp := new(KeyPairs)

	skp.EcdsaKeyToBytes(spri, DefaultCurve)
	ekp.EciesKeyToBytes(epri, DefaultCurve)

	// test the the saving and load of ecdsa key
	err := skp.SaveKeyToFile("ecdsa")
	if err != nil {
		panic(err)
	}

	fp1, err := LoadEcdsaKeyFromFile("ecdsa")
	if err != nil {
		panic(err)
	}

	flag := cmpEcdsaPrivate(spri, fp1)
	if flag == false {
		fmt.Println("ErrcmpEcdsaPrivate")
	}

	//test the the saving and load of ecies key
	err = ekp.SaveKeyToFile("ecies")
	if err != nil {
		panic(err)
	}
	fp2, err := LoadEciesKeyFromFile("ecies")
	if err != nil {
		panic(err)
	}
	flag = cmpEciesPrivate(epri, fp2)
	if flag == false {
		fmt.Println("ErrcmpEciesPrivate")
	}
}

func TestUpdateEciesKey(t *testing.T) {

	err := UpdateEciesKey("ecies", rand.Reader, DefaultCurve)
	if err != nil {
		panic(err)
	}
}