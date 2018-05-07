package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"genaro-crypto/client"
	"genaro-crypto/crypto"
	"genaro-crypto/kdc"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// encrypt contract data formed as key-values
func EncContract(fileid []byte, keys KeyWithPub, kvs map[string]string) (num int, err error) {
	num = 0

	// connect database host
	session, err := mgo.Dial("localhost")
	if err != nil {
		return num, errors.New("failed to connect with local host")
	}
	defer session.Close()

	file := hex.EncodeToString(fileid)
	ec := session.DB(EkvDB).C(file)

	key0, _ := hex.DecodeString(keys.Key0)
	key1, _ := hex.DecodeString(keys.Key1)
	key2, _ := hex.DecodeString(keys.Key2)

	bkey := &kdc.SubKey{
		Subk0: key0,
		Subk1: key1,
		Subk2: key2,
	}

	for key, value := range kvs {
		kv := &client.KeyValue{
			Key:   []byte(key),
			Value: []byte(value),
		}
		ekv, err := client.EncryptKeyValue(bkey, kv)
		if err != nil {
			return num, err
		}

		ssek := hex.EncodeToString(ekv.SSEKey)
		ek := hex.EncodeToString(ekv.EKey)
		ev := hex.EncodeToString(ekv.EValue)

		err = ec.Insert(&EkeyValue{keys.Pub, ssek, ek, ev})
		if err != nil {
			return num, err
		}

		num++
	}
	return
}

// decrypt all encrypted key-values
func DecWithPrint(fileid []byte, keys []KeyWithPub) (num int, err error) {
	num = 0

	session, err := mgo.Dial("localhost")
	if err != nil {
		return num, errors.New("failed to connect with local host")
	}
	defer session.Close()

	file := hex.EncodeToString(fileid)
	ec := session.DB(EkvDB).C(file)

	for _, key := range keys {
		var ekvs []EkeyValue

		err = ec.Find(bson.M{"pub": key.Pub}).All(&ekvs)
		if err != nil {
			return num, errors.New("something wrong with ekvs search")
		}

		for _, ele := range ekvs {
			ek, _ := hex.DecodeString(ele.EKey)
			ev, _ := hex.DecodeString(ele.EValue)

			ekv := &client.EnKeyValue{
				EKey:   ek,
				EValue: ev,
			}

			key0, _ := hex.DecodeString(key.Key0)
			dek := &kdc.SubKey{
				Subk0: key0,
			}

			kv, err := client.DecryptKeyValue(dek, ekv)
			if err != nil {
				return num, err
			}

			fmt.Printf("%s, %s\n", kv.Key, kv.Value)
			num++
		}
	}
	return
}

// Search for the specified key, and return the corresponding values
func Search(tokens []Token, fileid []byte) (evs []EValues, num int, err error) {
	num = 0

	session, err := mgo.Dial("localhost")
	if err != nil {
		return nil, num, errors.New("failed to connect with local host")
	}
	defer session.Close()

	file := hex.EncodeToString(fileid)
	ec := session.DB(EkvDB).C(file)

	var ekvs []EkeyValue

	for _, token := range tokens {
		pub := hex.EncodeToString(token.Pub)

		err = ec.Find(bson.M{"pub": pub}).All(&ekvs)
		if err != nil {
			return nil, num, errors.New("something wrong with ekvs search")
		}

		var temp [][]byte
		for _, ele := range ekvs {
			ssek, _ := hex.DecodeString(ele.SSEKey)
			ev, _ := hex.DecodeString(ele.EValue)

			if crypto.Matching(token.Token, ssek) {
				temp = append(temp, ev)
				num++
			}
		}
		if temp != nil {
			evl := EValues{
				Pub: token.Pub,
				EVs: temp,
			}
			evs = append(evs, evl)
		}
	}
	return
}

// decrypt encrypted values
func DecEValues(keys []KeyWithPub, evs []EValues) (vs [][]byte, num int, err error) {
	num = 0

	for _, key := range keys {
		pub, _ := hex.DecodeString(key.Pub)
		k0, _ := hex.DecodeString(key.Key0)

		for _, ev := range evs {
			if bytes.Equal(pub, ev.Pub) {
				for _, ele := range ev.EVs {
					v, err := crypto.AESDecryptOFB(k0, ele)
					if err != nil {
						return vs, num, err
					}
					vs = append(vs, v)
					num++
				}
			}
		}
	}
	return
}
