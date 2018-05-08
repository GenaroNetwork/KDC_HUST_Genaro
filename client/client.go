package client

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"genaro-crypto/crypto"
	"genaro-crypto/kdc"
	"genaro-crypto/protobuf"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/golang/protobuf/proto"
)

type GenaroUser struct {
	Epri *ecies.PrivateKey
	Spri *ecdsa.PrivateKey
}

type KeyValue struct {
	Key, Value []byte
}

// The ciphertext form of key-value pair
type EnKeyValue struct {
	SSEKey []byte // searchable ciphertext of key
	EKey   []byte // ciphertext of key
	EValue []byte // ciphertext of value
}

// LoadAsyKey initializes user by loading two keys from local file
func (user *GenaroUser) LoadAsyKey(ecdsapath, eciespath string) (err error) {
	user.Spri, err = crypto.LoadEcdsaKeyFromFile(ecdsapath)
	if err != nil {
		return err
	}
	user.Epri, err = crypto.LoadEciesKeyFromFile(eciespath)
	if err != nil {
		return err
	}
	return nil
}

// EncryptKeyValue encrypts key-value pair by symmetrical keys from kdc
func EncryptKeyValue(keys *kdc.SubKey, kv *KeyValue) (ekv *EnKeyValue, err error) {
	ekey, err := crypto.AESEncryptOFB(keys.EKey, kv.Key)
	if err != nil {
		return nil, fmt.Errorf("EncryptKeyValue: failed to encrypt key with error: %s", err.Error())
	}

	evalue, err := crypto.AESEncryptOFB(keys.EKey, kv.Value)
	if err != nil {
		return nil, fmt.Errorf("EncryptKeyValue: failed to encrypt value with error: %s", err.Error())
	}

	ssekey, err := crypto.SearchableEnc(kv.Key, keys.SKey)
	if err != nil {
		return nil, fmt.Errorf("EncryptKeyValue: failed to generate searchable ciphertext with error: %s", err.Error())
	}

	ekv = &EnKeyValue{
		SSEKey: ssekey,
		EKey:   ekey,
		EValue: evalue,
	}
	return
}

// DecryptKeyValue decrypts ciphertext of key-value pair, and ignores the searchable ciphertext
func DecryptKeyValue(keys *kdc.SubKey, ekv *EnKeyValue) (kv *KeyValue, err error) {
	key, err := crypto.AESDecryptOFB(keys.EKey, ekv.EKey)
	if err != nil {
		return nil, fmt.Errorf("DecryptKeyValue: failed to decrypt key with error: %s", err.Error())
	}

	value, err := crypto.AESDecryptOFB(keys.EKey, ekv.EValue)
	if err != nil {
		return nil, fmt.Errorf("DecryptKeyValue: failed to decrypt value with error: %s", err.Error())
	}

	kv = &KeyValue{
		Key:   key,
		Value: value,
	}
	return
}

// GetResponseA handles the response of Request A
func (user *GenaroUser) GetResponseA(rep []byte, path string,
	pub *ecdsa.PublicKey,
) (ans, fileid []byte, keys *kdc.SubKey, err error) {
	rp := &protobuf.Response{}
	err = proto.Unmarshal(rep, rp)
	if err != nil {
		return nil, nil, nil, errors.New("GetResponseA: failed to unmarshal response-buffer")
	}

	msg := make([]byte, 1+len(rp.Cora))
	copy(msg, rp.Type)
	copy(msg[1:], rp.Cora)

	// Verify Signature
	if !crypto.VerifySignature(msg, rp.Smsg, pub) {
		return nil, nil, nil, errors.New("GetResponseA: failed to verify signature")
	}

	// Return the reason why kdc rejected
	if bytes.Equal(rp.Type, []byte{0X00}) {
		return rp.Cora, nil, nil, nil
	}

	if !bytes.Equal(rp.Type, []byte{0Xab}) {
		return nil, nil, nil, errors.New("GetResponseA: wrong response-buffer")
	}

	// Request was responded correctly. m = EKey||SKey||fileid
	m, err := crypto.EciesDecrypt(rp.Cora, user.Epri)
	if err != nil {
		return nil, nil, nil, errors.New("GetResponseA: something wrong with decryption")
	}

	// load signature of nonce from local file
	_, sn, err := LoadNonce(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("GetResponseA: failed to load nonce with error: %s", err.Error())
	}

	fileid = make([]byte, len(m[crypto.EKeyLen+crypto.SKeyLen:]))
	copy(fileid, m[crypto.EKeyLen+crypto.SKeyLen:])
	loadid := crypto.SHA1(sn)
	if !bytes.Equal(fileid, loadid[:]) {
		return nil, nil, nil, errors.New("GetResponseA: not wanted fileid")
	}

	keys = &kdc.SubKey{
		EKey: m[:crypto.EKeyLen],
		SKey: m[crypto.EKeyLen : crypto.EKeyLen+crypto.SKeyLen],
	}
	return
}

// GetResponseB dandles the response of Request B
func (user *GenaroUser) GetResponseB(rep, fileid []byte, pub *ecdsa.PublicKey,
) (ans []byte, keys *kdc.SubKey, err error) {
	rp := &protobuf.Response{}
	err = proto.Unmarshal(rep, rp)
	if err != nil {
		return nil, nil, errors.New("GetResponseB: failed to unmarshal response-buffer")
	}

	msg := make([]byte, 1+len(rp.Cora))
	copy(msg, rp.Type)
	copy(msg[1:], rp.Cora)

	// Verify Signature
	if !crypto.VerifySignature(msg, rp.Smsg, pub) {
		return nil, nil, errors.New("GetResponseB: failed to verify signature")
	}

	// Return the reason why kdc rejected
	if bytes.Equal(rp.Type, []byte{0X00}) {
		return rp.Cora, nil, nil
	}

	if !bytes.Equal(rp.Type, []byte{0Xab}) {
		return nil, nil, errors.New("GetResponseB: wrong response-buffer")
	}

	// Request was responded correctly. m = EKey||SKey||fileid
	m, err := crypto.EciesDecrypt(rp.Cora, user.Epri)
	if err != nil {
		return nil, nil, errors.New("GetResponseB: something wrong with decryption")
	}

	fid := make([]byte, len(m[crypto.EKeyLen+crypto.SKeyLen:]))
	copy(fid, m[crypto.EKeyLen+crypto.SKeyLen:])
	if !bytes.Equal(fileid, fid) {
		return nil, nil, errors.New("GetResponseB: not wanted fileid")
	}

	keys = &kdc.SubKey{
		EKey: m[:crypto.EKeyLen],
		SKey: m[crypto.EKeyLen : crypto.EKeyLen+crypto.SKeyLen],
	}
	return
}

//  GetResponseC handles the response of Request C
func (user *GenaroUser) GetResponseC(rep []byte, pub *ecdsa.PublicKey) (ans []byte, state bool, err error) {
	rp := &protobuf.Response{}
	err = proto.Unmarshal(rep, rp)
	if err != nil {
		return nil, false, errors.New("GetResponseC: failed to unmarshal response-buffer")
	}

	msg := make([]byte, 1+len(rp.Cora))
	copy(msg, rp.Type)
	copy(msg[1:], rp.Cora)

	// Verify Signature
	if !crypto.VerifySignature(msg, rp.Smsg, pub) {
		return nil, false, errors.New("GetResponseC: failed to verify signature")
	}

	// Return the reason why kdc rejected
	if bytes.Equal(rp.Type, []byte{0X00}) {
		return rp.Cora, false, nil
	}

	if !bytes.Equal(rp.Type, []byte{0Xcd}) {
		return nil, false, errors.New("GetResponseC: wrong response-buffer")
	}

	//return RSRES
	return rp.Cora, true, nil
}

// Currently, there is no need for KDC to reply to Request D
// GetResponseE dandles the response of Request E
func (user *GenaroUser) GetResponseE(rep, fileid []byte, pub *ecdsa.PublicKey,
) (ans []byte, keys []*kdc.KeyOwner, err error) {
	rp := &protobuf.Response{}
	err = proto.Unmarshal(rep, rp)
	if err != nil {
		return nil, nil, errors.New("GetResponseC: failed to unmarshal response-buffer")
	}

	eks := kdc.EkeysToBytes(rp.Keys)

	msg := make([]byte, 1+len(rp.Cora)+len(eks))
	copy(msg, rp.Type)
	copy(msg[1:], rp.Cora)
	copy(msg[1+len(rp.Cora):], eks)

	// Verify Signature
	if !crypto.VerifySignature(msg, rp.Smsg, pub) {
		return nil, nil, errors.New("GetResponseC: failed to verify signature")
	}

	// Return the reason why kdc rejected
	if bytes.Equal(rp.Type, []byte{0X00}) {
		return rp.Cora, nil, nil
	}

	if !bytes.Equal(rp.Type, []byte{0Xef}) {
		return nil, nil, errors.New("GetResponseC: wrong response-buffer")
	}

	if !bytes.Equal(fileid, rp.Cora) {
		return nil, nil, errors.New("GetResponseC: not wanted fileid")
	}

	for _, ko := range rp.Keys {
		m, err := crypto.EciesDecrypt(ko.Enk, user.Epri)
		if err != nil {
			return nil, nil, errors.New("GetResponseC: something wrong with decryption")
		}
		ele := &kdc.KeyOwner{
			Pub: ko.Pub,
			SubKey: kdc.SubKey{
				EKey: m[:crypto.EKeyLen],
				SKey: m[crypto.EKeyLen : crypto.EKeyLen+crypto.SKeyLen],
			},
		}
		keys = append(keys, ele)
	}
	return nil, keys, nil
}
