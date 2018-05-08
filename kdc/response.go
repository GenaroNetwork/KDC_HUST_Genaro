// There are four kinds of responses
// NegativeResponse: 0x00 kdc rejects the request of user
// PositiveResponse: 0xcd kdc responds the executing state for RequestC
// ExpectedResponse: 0xab kdc returns the the corresponding keys for RequestA or RequestB
// AllKeysResponse:  0xef kdc returns all keys for RequestE
// Note that the RequestD has no need to respond

package kdc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"genaro-crypto/crypto"
	"genaro-crypto/protobuf"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/golang/protobuf/proto"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// ResopndToRequest is a high level encapsulation for kdc functions
// if response == err == nil, it means that  there is no need to respond
func ResopndToRequest(request []byte, pri *ecdsa.PrivateKey) (response []byte, err error) {
	req := &protobuf.Request{}
	err = proto.Unmarshal(request, req)
	if err != nil {
		return nil, err
	}

	// verify request buffer
	list := bytes.Join(req.List, []byte(""))
	msg := make([]byte, 1+len(req.Norf)+len(req.Snon)+len(req.Enpk)+len(list))
	copy(msg, req.Type)
	copy(msg[1:], req.Norf)
	copy(msg[1+len(req.Norf):], req.Snon)
	copy(msg[1+len(req.Norf)+len(req.Snon):], req.Enpk)
	copy(msg[1+len(req.Norf)+len(req.Snon)+len(req.Enpk):], list)
	if !crypto.VerifySignNoPub(msg, req.Smsg) {
		return NegativeResponse([]byte("Request has been tampered"), pri)
	}

	// handle RequestA
	if bytes.Equal(req.Type, []byte{0xa1}) {
		pub := crypto.BytesToEciesPub(req.Enpk, crypto.DefaultCurve)
		return HandleRequestA(msg, req, pub, pri)
	}

	// handle RequestB
	if bytes.Equal(req.Type, []byte{0xb2}) {
		spub, _ := crypto.PubFromSign(msg, req.Smsg)
		epub := crypto.BytesToEciesPub(req.Enpk, crypto.DefaultCurve)
		return HandleRequestB(req.Norf, spub, epub, pri)
	}

	// handle RequestC
	if bytes.Equal(req.Type, []byte{0xc3}) {
		spub, _ := crypto.PubFromSign(msg, req.Smsg)
		return HandleRequestC(req.Norf, spub, req.List, pri)
	}

	// handle RequestD
	if bytes.Equal(req.Type, []byte{0xd4}) {
		spub, _ := crypto.PubFromSign(msg, req.Smsg)
		// no need to reply to request D
		return nil, HandleRequestD(req.Norf, spub)
	}

	// handle RequestE
	if bytes.Equal(req.Type, []byte{0xe5}) {
		spub, _ := crypto.PubFromSign(msg, req.Smsg)
		epub := crypto.BytesToEciesPub(req.Enpk, crypto.DefaultCurve)
		return HandleRequestE(req.Norf, spub, epub, pri)
	}

	return nil, nil
}

func HandleRequestA(msg []byte,
	req *protobuf.Request,
	pub *ecies.PublicKey,
	pri *ecdsa.PrivateKey) ([]byte, error) {

	//verify whether  the two public keys from Snon and Smsg are the same
	pub1, err := crypto.PubFromSign(req.Norf, req.Snon)
	if err != nil {
		return NegativeResponse([]byte("Bad signature of nonce"), pri)
	}
	pub2, _ := crypto.PubFromSign(msg, req.Smsg)
	if !bytes.Equal(pub1, pub2) {
		return NegativeResponse([]byte("Illegal request"), pri)
	}

	// connect database host
	session, err := mgo.Dial("localhost")
	if err != nil {
		return nil, errors.New("HandleRequestA: failed to connect with local host")
	}
	defer session.Close()

	mdb := session.DB(MskDB)
	sdb := session.DB(SaltDB)

	// It must be a protogenous request from a contract builder
	// generate fileid
	fileid := crypto.SHA1(req.Snon)
	msk, _ := GetMasterKey(mdb, fileid[:])
	if msk != nil {
		// It is a repeated request and associated data has been stored.
		// generate sub keys
		subk, err := GenSubKey(sdb, msk, fileid[:], pub1)
		if err != nil {
			return nil, errors.New("HandleRequestA: something wrong with sub keys generation")
		}

		// return an expected response
		return ExpectedResponse(fileid[:], subk, pub, pri)
	}

	// It is a new request
	msk, err = GenMasterKey(mdb, fileid[:], pub1)
	if err != nil {
		return nil, errors.New("HandleRequestA: something wrong with master key generation")
	}

	//generate sub keys
	subk, err := GenSubKey(sdb, msk, fileid[:], pub1)
	if err != nil {
		return nil, errors.New("HandleRequestA: something wrong with sub keys generation")
	}

	// save whitelist
	wdb := session.DB(WilDB)
	err = SaveWhitelist(wdb, fileid[:], pub1, req.List)
	if err != nil {
		return nil, errors.New("HandleRequestA: something wrong with whitelist saving")
	}

	// return an expected response
	return ExpectedResponse(fileid[:], subk, pub, pri)
}

func HandleRequestB(fileid, spub []byte,
	epub *ecies.PublicKey,
	kpri *ecdsa.PrivateKey) ([]byte, error) {

	// connect database host
	session, err := mgo.Dial("localhost")
	if err != nil {
		return nil, errors.New("HandleRequestB: failed to connect with local host")
	}
	defer session.Close()

	wdb := session.DB(WilDB)

	// check for permissions
	if !CheckWhitelist(wdb, fileid, spub) {
		return NegativeResponse([]byte("Permission denied"), kpri)
	}

	//get master key
	mdb := session.DB(MskDB)
	msk, err := GetMasterKey(mdb, fileid)
	if err != nil {
		return NegativeResponse([]byte("No such fileid in kdc"), kpri)
	}

	//generate sub keys
	sdb := session.DB(SaltDB)
	subk, err := GenSubKey(sdb, msk, fileid[:], spub)
	if err != nil {
		return nil, errors.New("HandleRequestB: something wrong with sub keys generation")
	}

	// return an expected response
	return ExpectedResponse(fileid, subk, epub, kpri)
}

func HandleRequestC(fileid, pub []byte,
	list [][]byte,
	kpri *ecdsa.PrivateKey) ([]byte, error) {

	// connect database host
	session, err := mgo.Dial("localhost")
	if err != nil {
		return nil, errors.New("HandleRequestC: failed to connect with local host")
	}
	defer session.Close()

	c := session.DB(WilDB).C(WilCol)

	// check for permissions
	result := new(WhiteList)
	spub := hex.EncodeToString(pub)
	id := hex.EncodeToString(fileid)
	err = c.Find(bson.M{"file": id, "owner": spub}).One(&result)
	if err != nil {
		// only owner can update the whitelist
		return NegativeResponse([]byte("Permission denied"), kpri)
	}

	counter := 0
	for _, pub := range list {
		err := UpdateWhitelist(c, fileid, pub)
		if err == nil {
			counter++
			continue
		}
		if err == ErrPubExist {
			// the added public key is existed
			continue
		}
		return nil, err
	}

	statue := fmt.Sprintf("%d new pubs have been added successfully", counter)

	// return an expected response
	return PositiveResponse([]byte(statue), kpri)
}

func HandleRequestD(fileid, pub []byte) error {

	// connect database host
	session, err := mgo.Dial("localhost")
	if err != nil {
		return errors.New("HandleRequestD: failed to connect with local host")
	}
	defer session.Close()

	c := session.DB(WilDB).C(WilCol)

	// check for permissions
	result := new(WhiteList)
	spub := hex.EncodeToString(pub)
	id := hex.EncodeToString(fileid)
	err = c.Find(bson.M{"file": id, "owner": spub}).One(&result)
	if err != nil {
		// this is a null response, and kdc will do nothing
		return nil
	}

	// add the fileid of expired contract into old list
	d := session.DB(OldDB)
	return AddOldList(d, fileid)
}

func HandleRequestE(fileid, spub []byte,
	epub *ecies.PublicKey,
	kpri *ecdsa.PrivateKey) ([]byte, error) {

	// connect database host
	session, err := mgo.Dial("localhost")
	if err != nil {
		return nil, errors.New("HandleRequestE: failed to connect with local host")
	}
	defer session.Close()

	msd := session.DB(MskDB)
	sud := session.DB(SupDB)
	sad := session.DB(SaltDB)

	kos, err := ReturnAllKeys(msd, sud, sad, fileid, spub)
	if err == ErrNoAccess {
		return NegativeResponse([]byte("Permission denied"), kpri)
	}
	if err == ErrNoFileid {
		return NegativeResponse([]byte("No such fileid in kdc"), kpri)
	}
	if err == nil {
		return AllKeysResponse(fileid, kos, epub, kpri)
	}
	return nil, err
}

// 0xab, respond keys which belong to the pub
func ExpectedResponse(fileid []byte,
	keys *SubKey,
	pub *ecies.PublicKey,
	pri *ecdsa.PrivateKey) ([]byte, error) {

	ty := []byte{0xab}

	// assemble response
	m := make([]byte, crypto.EKeyLen+crypto.SKeyLen+len(fileid))
	copy(m, keys.EKey)
	copy(m[crypto.EKeyLen:], keys.SKey)
	copy(m[crypto.EKeyLen+crypto.SKeyLen:], fileid)

	// encrypt keys and fileid by client's ecies public key
	c, err := crypto.EciesEncrypt(rand.Reader, pub, m)
	if err != nil {
		return nil, errors.New("ExpectedResponse: failed to encrypt keys and fileid")
	}

	// assemble message
	msg := make([]byte, 1+len(c))
	copy(msg, ty)
	copy(msg[1:], c)

	// sign message
	sign, err := crypto.SignMessage(msg, pri)
	if err != nil {
		return nil, fmt.Errorf("ExpectedResponse: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	rep := &protobuf.Response{
		Type: ty,
		Cora: c,
		Smsg: sign,
	}
	return proto.Marshal(rep)
}

// 0xcd respond the executing state
func PositiveResponse(state []byte, pri *ecdsa.PrivateKey) ([]byte, error) {
	ty := []byte{0xcd}

	// assemble messages
	msg := make([]byte, 1+len(state))
	copy(msg, ty)
	copy(msg[1:], state)

	// sign message
	sign, err := crypto.SignMessage(msg, pri)
	if err != nil {
		return nil, fmt.Errorf("PositiveResponse: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	rep := &protobuf.Response{
		Type: ty,
		Cora: state,
		Smsg: sign,
	}
	return proto.Marshal(rep)
}

// 0x00 Reject the request with some reasons
func NegativeResponse(reason []byte, pri *ecdsa.PrivateKey) ([]byte, error) {
	ty := []byte{0x00}

	// assemble messages
	msg := make([]byte, 1+len(reason))
	copy(msg, ty)
	copy(msg[1:], reason)

	// sign message
	sign, err := crypto.SignMessage(msg, pri)
	if err != nil {
		return nil, fmt.Errorf("NegativeResponse: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	rep := &protobuf.Response{
		Type: ty,
		Cora: reason,
		Smsg: sign,
	}
	return proto.Marshal(rep)
}

// 0xef respond all the keys of fileid
func AllKeysResponse(fileid []byte,
	keys []*KeyOwner,
	pub *ecies.PublicKey,
	pri *ecdsa.PrivateKey) ([]byte, error) {

	ty := []byte{0xef}

	// encapsulate all encrypted keys
	var ras []*protobuf.ResponseAllkeys
	for _, ko := range keys {
		k := make([]byte, crypto.EKeyLen+crypto.SKeyLen)
		copy(k, ko.EKey)
		copy(k[crypto.EKeyLen:], ko.SKey)

		// encrypt key by ecies pub
		ek, err := crypto.EciesEncrypt(rand.Reader, pub, k)
		if err != nil {
			return nil, errors.New("AllKeysResponse: failed to encrypt keys")
		}

		ele := &protobuf.ResponseAllkeys{
			Pub: ko.Pub,
			Enk: ek,
		}
		ras = append(ras, ele)
	}

	// assemble messages
	eks := EkeysToBytes(ras)
	msg := make([]byte, 1+len(fileid)+len(eks))
	copy(msg, ty)
	copy(msg[1:], fileid)
	copy(msg[1+len(fileid):], eks)

	// sign message
	sign, err := crypto.SignMessage(msg, pri)
	if err != nil {
		return nil, fmt.Errorf("AllKeysResponse: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	rep := &protobuf.Response{
		Type: ty,
		Cora: fileid,
		Keys: ras,
		Smsg: sign,
	}
	return proto.Marshal(rep)
}

// Assemble Keys list to bytes
func EkeysToBytes(ras []*protobuf.ResponseAllkeys) (ekb []byte) {
	for _, ek := range ras {
		for _, ele := range ek.Pub {
			ekb = append(ekb, ele)
		}

		for _, ele := range ek.Enk {
			ekb = append(ekb, ele)
		}
	}
	return
}
