// There are six kinds of test cases.
// TestCoreFunctions is to test encryption, decryption and search without interaction
// TestUploadContract is to test contract encryption and interaction
// TestModifyContract is to test contract modification and interaction
// TestUpdateWhitelist is to test whitelist update and interaction
// TestDecryptContract is to test contract decryption and interaction
// TestSearchContract is to test encrypted contract search and interaction
// Note that the interaction is just between client and kdc

package main

import (
	"encoding/hex"
	"genaro-crypto/crypto"
	"fmt"
	"genaro-crypto/client"
	"bytes"
	"genaro-crypto/kdc"
)

func TestCoreFunctions() {
	fmt.Printf("begin encryption test\n")
	TestEncrypt()

	fmt.Printf("begin decryption test\n")
	TestDecrypt()

	fmt.Printf("begin modification test\n")
	TestModify()

	fmt.Printf("begin decryption test again\n")
	TestDecrypt()

	fmt.Printf("begain search test\n")
	TestSearch()
	fmt.Printf("TestCoreFunctions ends\n\n")
}

func TestEncrypt() {
	id, _ := hex.DecodeString(fileid)

	//encrypt initial json file
	kvs, num, err := ParseJson(ACreat)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d key-values have been parsed\n", num)

	num , err = EncContract(id, testkeys[0], kvs)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d key-values have been encrypted\n\n", num)
}

func TestDecrypt() {
	id, _ := hex.DecodeString(fileid)

	num, err := DecWithPrint(id, testkeys)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d encrypted key-values have been decrypted\n\n", num)
}

func TestModify() {
	id, _ := hex.DecodeString(fileid)

	// modified by A
	kvsa, numa, err := ParseJson(AChange)
	if err != nil {
		panic(err)
	}
	fmt.Printf("A modified %d key-values\n", numa)
	numa, err = EncContract(id, testkeys[0], kvsa)
	if err != nil {
		panic(err)
	}
	fmt.Printf("D's %d modified key-values have been encrypted\n", numa)

	// modified by B
	kvsb, numb, err := ParseJson(BChange)
	if err != nil {
		panic(err)
	}
	fmt.Printf("B modified %d key-values\n", numb)
	numb, err = EncContract(id, testkeys[1], kvsb)
	if err != nil {
		panic(err)
	}
	fmt.Printf("B's %d modified key-values have been encrypted\n", numb)

	// modified by C
	kvsc, numc, err := ParseJson(CChange)
	if err != nil {
		panic(err)
	}
	fmt.Printf("C modified %d key-values\n", numc)
	numc, err = EncContract(id, testkeys[2], kvsc)
	if err != nil {
		panic(err)
	}
	fmt.Printf("C's %d modified key-values have been encrypted\n\n", numc)

	// modified by A again
	kvsaa, numaa, err := ParseJson(AChangeA)
	if err != nil {
		panic(err)
	}
	fmt.Printf("A modified %d key-values again\n", numaa)
	numaa, err = EncContract(id, testkeys[0], kvsaa)
	if err != nil {
		panic(err)
	}
	fmt.Printf("C's %d newest modified key-values have been encrypted\n\n", numaa)
}

func TestSearch() {
	// generate tokens
	var tokens []Token
	for _, key := range testkeys {
		pub, _ := hex.DecodeString(key.Pub)
		key1, _ := hex.DecodeString(key.Key1)
		key2, _ := hex.DecodeString(key.Key2)

		token, err := crypto.Trapdoor([]byte(keyword), key1, key2)
		if err != nil {
			panic(err)
		}

		ele := Token{
			Pub: pub,
			Token: token,
		}
		tokens = append(tokens, ele)
	}

	id, _ := hex.DecodeString(fileid)
	evs, nums, err := Search(tokens, id)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d encrypted values for %s have been found\n", nums, keyword)

	vs, numd, err := DecEValues(testkeys, evs)
	if err != nil {
		panic(err)
	}

	if nums != numd {
		fmt.Println("something wrong with decrypting values")
	}

	for _, v := range vs {
		fmt.Printf("value: %s\n", string(v))
	}
}

func TestUploadContract() {
	ecdsapath  := keypairspath + "/ecdsaA"
	eciespath  := keypairspath + "/eciesA"
	kecdsapath := keypairspath + "/ecdsakdc"
	noncepath  := keypairspath + "/nonce"

	// init genaro user
	user := new(client.GenaroUser)
	err := user.LoadAsyKey(ecdsapath, eciespath)
	if err != nil {
		panic(err)
	}

	var list [][]byte
	for _, pub := range whitelist {
		p, _ := hex.DecodeString(pub)
		list = append(list, p)
	}

	// first request
	buf, err := user.CallRequestA(list, noncepath)

	// recall request
	rbuf, err := user.ReCallRequestA(list, noncepath)

	if !bytes.Equal(buf, rbuf) {
		fmt.Println("the two buffer should be same!")
	}

	// load the ecdsa key of kdc
	kpri, err := crypto.LoadEcdsaKeyFromFile(kecdsapath)
	if err != nil {
		panic(err)
	}

	// respond by kdc
	rep, err := kdc.ResopndToRequest(buf, kpri)
	if err != nil {
		panic(err)
	}

	// parse request
	ans, fileid, keys, err := user.GetResponseA(rep, noncepath, &kpri.PublicKey)
	if err != nil {
		panic(err)
	}

	id := hex.EncodeToString(fileid)
	key0 := hex.EncodeToString(keys.Subk0)
	key1 := hex.EncodeToString(keys.Subk1)
	key2 := hex.EncodeToString(keys.Subk2)
	fmt.Printf("ans:%s\nfileid:%s\nkey0:%s\nkey1:%s\nkey2:%s\n",string(ans),id,key0,key1,key2)

	owner := crypto.EcdsaPubToBytes(&user.Spri.PublicKey, crypto.DefaultCurve)
	pub := hex.EncodeToString(owner)
	kw := KeyWithPub{
		Pub: pub,
		Key0: key0,
		Key1: key1,
		Key2: key2,
	}

	// parse json file
	kvs, num, err := ParseJson(ACreat)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d key-values have been parsed\n", num)

	// encrypt contract
	num , err = EncContract(fileid, kw, kvs)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d key-values have been encrypted\n", num)
	fmt.Printf("TestUploadContract ends\n\n")
}

func getFileid(noncepath string) ([]byte, error) {
	_, sn, err := client.LoadNonce(noncepath)
	if err != nil {
		return nil, err
	}

	fileid := crypto.SHA1(sn)
	return fileid[:], nil
}

func TestModifyContract() {
	ecdsapath  := keypairspath + "/ecdsaB"
	eciespath  := keypairspath + "/eciesB"
	kecdsapath := keypairspath + "/ecdsakdc"
	noncepath  := keypairspath + "/nonce"

	// init genaro user
	user := new(client.GenaroUser)
	err := user.LoadAsyKey(ecdsapath, eciespath)
	if err != nil {
		panic(err)
	}

	fileid, err := getFileid(noncepath)
	if err != nil {
		panic(err)
	}

	// call for keys
	buf, err := user.CallRequestB(fileid)


	// load the ecdsa key of kdc
	kpri, err := crypto.LoadEcdsaKeyFromFile(kecdsapath)
	if err != nil {
		panic(err)
	}

	// respond by kdc
	rep, err := kdc.ResopndToRequest(buf, kpri)
	if err != nil {
		panic(err)
	}

	// parse request
	ans, keys, err := user.GetResponseB(rep, fileid, &kpri.PublicKey)
	if err != nil {
		panic(err)
	}

	key0 := hex.EncodeToString(keys.Subk0)
	key1 := hex.EncodeToString(keys.Subk1)
	key2 := hex.EncodeToString(keys.Subk2)
	fmt.Printf("ans:%s\nkey0:%s\nkey1:%s\nkey2:%s\n",string(ans),key0,key1,key2)

	owner := crypto.EcdsaPubToBytes(&user.Spri.PublicKey, crypto.DefaultCurve)
	pub := hex.EncodeToString(owner)
	kw := KeyWithPub{
		Pub: pub,
		Key0: key0,
		Key1: key1,
		Key2: key2,
	}

	// parse json file
	kvs, num, err := ParseJson(BChange)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d key-values have been parsed\n", num)

	// encrypt contract
	num , err = EncContract(fileid, kw, kvs)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d key-values have been encrypted\n", num)
	fmt.Printf("TestModifyContract ends\n\n")
}

func TestUpdateWhitelist() {
	ecdsapath  := keypairspath + "/ecdsaA"
	eciespath  := keypairspath + "/eciesA"
	kecdsapath := keypairspath + "/ecdsakdc"
	noncepath  := keypairspath + "/nonce"

	// init genaro user
	user := new(client.GenaroUser)
	err := user.LoadAsyKey(ecdsapath, eciespath)
	if err != nil {
		panic(err)
	}

	fileid, err := getFileid(noncepath)
	if err != nil {
		panic(err)
	}

	var nlist [][]byte
	for _, pub := range nwhitelist {
		p, _ := hex.DecodeString(pub)
		nlist = append(nlist, p)
	}

	// update whitelist
	buf, err := user.CallRequestC(fileid, nlist)


	// load the ecdsa key of kdc
	kpri, err := crypto.LoadEcdsaKeyFromFile(kecdsapath)
	if err != nil {
		panic(err)
	}

	// respond by kdc
	rep, err := kdc.ResopndToRequest(buf, kpri)
	if err != nil {
		panic(err)
	}

	// parse request
	ans, statue, err := user.GetResponseC(rep, &kpri.PublicKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ans:%s\nstatue:%t\n",ans, statue)
	fmt.Printf("TestUpdateWhitelist ends\n\n")
}


func TestDecryptContract() {
	ecdsapath  := keypairspath + "/ecdsaA"
	eciespath  := keypairspath + "/eciesA"
	kecdsapath := keypairspath + "/ecdsakdc"
	noncepath  := keypairspath + "/nonce"

	// init genaro user
	user := new(client.GenaroUser)
	err := user.LoadAsyKey(ecdsapath, eciespath)
	if err != nil {
		panic(err)
	}

	fileid, err := getFileid(noncepath)
	if err != nil {
		panic(err)
	}

	var list [][]byte
	for _, pub := range whitelist {
		p, _ := hex.DecodeString(pub)
		list = append(list, p)
	}

	// call for keys
	buf, err := user.CallRequestE(fileid)

	// load the ecdsa key of kdc
	kpri, err := crypto.LoadEcdsaKeyFromFile(kecdsapath)
	if err != nil {
		panic(err)
	}

	// respond by kdc
	rep, err := kdc.ResopndToRequest(buf, kpri)
	if err != nil {
		panic(err)
	}

	// parse request
	ans, keys, err := user.GetResponseE(rep, fileid, &kpri.PublicKey)
	if err != nil {
		panic(err)
	}

	if ans != nil {
		panic(ans)
	}

	var kws []KeyWithPub
	for _, key := range keys {
		pub := hex.EncodeToString(key.Pub)
		key0 := hex.EncodeToString(key.SubKey.Subk0)
		key1 := hex.EncodeToString(key.SubKey.Subk1)
		key2 := hex.EncodeToString(key.SubKey.Subk2)
		fmt.Printf("owner:%s\nkey0:%s\nkey1:%s\nkey2:%s\n",pub,key0,key1,key2)

		kw := KeyWithPub{
			Pub: pub,
			Key0: key0,
			Key1: key1,
			Key2: key2,
		}
		kws = append(kws, kw)
	}

	// decrypt key-values
	num, err := DecWithPrint(fileid, kws)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d encrypted key-values have been decrypted\n", num)
	fmt.Printf("TestDecryptContract ends\n\n")
}

func TestSearchContract(keyword string) {
	ecdsapath  := keypairspath + "/ecdsaA"
	eciespath  := keypairspath + "/eciesA"
	kecdsapath := keypairspath + "/ecdsakdc"
	noncepath  := keypairspath + "/nonce"

	// init genaro user
	user := new(client.GenaroUser)
	err := user.LoadAsyKey(ecdsapath, eciespath)
	if err != nil {
		panic(err)
	}

	fileid, err := getFileid(noncepath)
	if err != nil {
		panic(err)
	}

	var list [][]byte
	for _, pub := range whitelist {
		p, _ := hex.DecodeString(pub)
		list = append(list, p)
	}

	// call for keys
	buf, err := user.CallRequestE(fileid)

	// load the ecdsa key of kdc
	kpri, err := crypto.LoadEcdsaKeyFromFile(kecdsapath)
	if err != nil {
		panic(err)
	}

	// respond by kdc
	rep, err := kdc.ResopndToRequest(buf, kpri)
	if err != nil {
		panic(err)
	}

	// parse request
	ans, keys, err := user.GetResponseE(rep, fileid, &kpri.PublicKey)
	if err != nil {
		panic(err)
	}

	if ans != nil {
		panic(ans)
	}

	// generate tokens
	var kws []KeyWithPub
	var tokens []Token
	for _, key := range keys {
		token, err := crypto.Trapdoor([]byte(keyword), key.SubKey.Subk1, key.SubKey.Subk2)
		if err != nil {
			panic(err)
		}

		ele := Token{
			Pub: key.Pub,
			Token: token,
		}
		tokens = append(tokens, ele)

		pub := hex.EncodeToString(key.Pub)
		key0 := hex.EncodeToString(key.SubKey.Subk0)
		key1 := hex.EncodeToString(key.SubKey.Subk1)
		key2 := hex.EncodeToString(key.SubKey.Subk2)
		fmt.Printf("owner:%s\nkey0:%s\nkey1:%s\nkey2:%s\n",pub,key0,key1,key2)

		kw := KeyWithPub{
			Pub: pub,
			Key0: key0,
			Key1: key1,
			Key2: key2,
		}
		kws = append(kws, kw)
	}

	evs, nums, err := Search(tokens, fileid)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d encrypted values for %s have been found\n", nums, keyword)

	vs, numd, err := DecEValues(kws, evs)
	if err != nil {
		panic(err)
	}

	if nums != numd {
		fmt.Println("something wrong with decrypting values")
	}

	for _, v := range vs {
		fmt.Printf("value: %s\n", string(v))
	}
	fmt.Printf("TestSearchContract ends\n\n")
}