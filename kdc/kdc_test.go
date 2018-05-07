package kdc

import (
	"encoding/hex"
	"fmt"
	"gopkg.in/mgo.v2"
	"testing"
)

var (
	testid = "5bf98c8eede891f1ab36a40e745f37c803ec69bc"

	owner = "041bcf290fa63d7279bddb8733f4684099bb21a33af2b34234c00bf249799aebcee0a195a509379f4815d6c5e3277ab73e6987c93fb22aca808b1f70d55ed4db5c"

	superlist = []string{"04c89dd3fe9094ca293caf78c63297267e0e2f7e9e0d8723b6b098aa393d9c9a52df68a96b51b3a6db5cb6011e59bf38b7a4b385a247ed0a6bb09a92ba54115b9f",
		"04be81d40309281c1932c0e25932f12edd66296c4d68ec759a41b599064808c980cd9c036a20a7658d376d489201d1821f24e156e358cb379f14b19a36e94086d0",
	}

	whitelist = []string{
		"04ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e1",
		"042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889",
		"0492ac50c4903599f1b03b11cf987032180ec8a190f7d7f53c0047aa63208d1b812bda9bb46a810ad90ba8c6a3df215dcbb369eefa07e86205eed35557edc2ab7a",
	}

	testDB = "kdctest"
)

func TestSaveSuperuser(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	db := session.DB(testDB)

	var list [][]byte
	for _, pub := range superlist {
		p, _ := hex.DecodeString(pub)
		list = append(list, p)
	}

	err = SaveSuperuser(db, list)
	if err != nil {
		panic(err)
	}
}

func TestCheckSuperuser(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	db := session.DB(testDB)

	test1, _ := hex.DecodeString(superlist[1])
	test2 := []byte("not in superlist")

	fmt.Println(CheckSuperuser(db, test1))
	fmt.Println(CheckSuperuser(db, test2))
}

func TestSaveWhitelist(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	db := session.DB(testDB)

	id, _ := hex.DecodeString(testid)
	ow, _ := hex.DecodeString(owner)

	var list [][]byte
	for _, pub := range whitelist {
		p, _ := hex.DecodeString(pub)
		list = append(list, p)
	}

	err = SaveWhitelist(db, id, ow, list)
	if err != nil {
		panic(err)
	}

}

func TestCheckWhitelist(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	db := session.DB(testDB)

	test1, _ := hex.DecodeString(whitelist[0])
	test2 := []byte("not in whitelist")
	test3, _ := hex.DecodeString(owner)

	id, _ := hex.DecodeString(testid)

	fmt.Println(CheckWhitelist(db, id, test1))
	fmt.Println(CheckWhitelist(db, id, test2))
	fmt.Println(CheckWhitelist(db, id, test3))

	c := db.C(WilCol)
	test4, _ := hex.DecodeString("047c1b0673ce332d61b97348d01c4d333f137db491aba4970f84e37acca8ae77ad179425557dfe9c5e75d852de851addedaede994201f8c1ad66ee93e87ae82ed3")

	err = UpdateWhitelist(c, id, test4)
	if err != nil {
		panic(err)
	}

	fmt.Println(CheckWhitelist(db, id, test4))
}

func TestAddOldList(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	db := session.DB(testDB)

	id, _ := hex.DecodeString(testid)

	err = AddOldList(db, id)
	if err != nil {
		panic(err)
	}
}

func TestKeyGenAndReturn(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	db := session.DB(testDB)

	id, _ := hex.DecodeString(testid)
	ow, _ := hex.DecodeString(owner)

	msk, err := GenMasterKey(db, id, ow)
	if err != nil {
		panic(err)
	}

	pub1, _ := hex.DecodeString(whitelist[0])
	pub2, _ := hex.DecodeString(whitelist[1])

	subk1, err := GenSubKey(db, msk, id, pub1)
	if err != nil {
		panic(err)
	}
	printSubKey(subk1)

	subk2, err := GenSubKey(db, msk, id, pub2)
	if err != nil {
		panic(err)
	}
	printSubKey(subk2)

	ko, err := ReturnAllKeys(db, db, db, id, ow)
	if err != nil {
		panic(err)
	}
	for _, key := range ko {
		fmt.Println(hex.EncodeToString(key.Pub))
		printSubKey(&key.SubKey)
	}

	_, err = ReturnAllKeys(db, db, db, id, pub1)
	if err != nil {
		fmt.Println(err)
	}

	pub3, _ := hex.DecodeString(superlist[1])
	ko1, err := ReturnAllKeys(db, db, db, id, pub3)
	if err != nil {
		panic(err)
	} else {
		for _, key := range ko1 {
			fmt.Println(hex.EncodeToString(key.Pub))
			printSubKey(&key.SubKey)
		}
	}

}

func printSubKey(key *SubKey) {
	fmt.Println("subkey0:" + hex.EncodeToString(key.Subk0))
	fmt.Println("subkey1:" + hex.EncodeToString(key.Subk1))
	fmt.Println("subkey2:" + hex.EncodeToString(key.Subk2))
}
