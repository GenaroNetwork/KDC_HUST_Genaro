// There are five kinds of user's requests to KDC
// RequestA: 0xa1 smart contract creator calls for keys
// RequestB: 0xb2 smart contract modifier calls for keys
// RequestC: 0xc3 smart contract creator adds new users into whitelist
// RequestD: 0xd4 smart contract creator informs KDC that the current contract has been completed
// RequestE: 0xe5 smart contract creator or superuser calls for all the maintainer's keys of the contract

package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"genaro-crypto/crypto"
	"genaro-crypto/protobuf"
	"github.com/golang/protobuf/proto"
	"io"
	"os"
)

var (
	DefaultCurve = crypto.DefaultCurve

	NonceSize = 8 // bytes
)

// CallRequestA returns a buffer of RequestA. The path is used to store nonce.
// Nonce will be imported when call RequestA again
func (user *GenaroUser) CallRequestA(list [][]byte, path string) ([]byte, error) {
	ty := []byte{0xa1}

	nonce, err := getNonce()
	if err != nil {
		return nil, errors.New("CallRequestA: failed to get nonce")
	}

	// sign nonce
	sn, err := crypto.SignMessage(nonce, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("CallRequestA: failed to sign nonce with error: %s", err.Error())
	}

	// save nonce and its signature
	err = SaveNonce(nonce, sn, path)
	if err != nil {
		return nil, fmt.Errorf("CallRequestA: failed to save nonce with error: %s", err.Error())
	}

	// assemble messages
	epk := crypto.EciesPubToBytes(&user.Epri.PublicKey, DefaultCurve)
	lb := bytes.Join(list, []byte(""))

	msg := make([]byte, 1+len(nonce)+len(sn)+len(epk)+len(lb))
	copy(msg, ty)
	copy(msg[1:], nonce)
	copy(msg[1+len(nonce):], sn)
	copy(msg[1+len(nonce)+len(sn):], epk)
	copy(msg[1+len(nonce)+len(sn)+len(epk):], lb)

	// sign message
	sign, err := crypto.SignMessage(msg, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("CallRequestA: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	req := &protobuf.Request{
		Type: ty,
		Norf: nonce,
		Snon: sn,
		Enpk: epk,
		List: list,
		Smsg: sign,
	}
	return proto.Marshal(req)
}

// CallRequestB returns a buffer of RequestB
func (user *GenaroUser) CallRequestB(fileid []byte) ([]byte, error) {
	ty := []byte{0xb2}

	// assemble messages
	epk := crypto.EciesPubToBytes(&user.Epri.PublicKey, DefaultCurve)

	msg := make([]byte, 1+len(fileid)+len(epk))
	copy(msg, ty)
	copy(msg[1:], fileid)
	copy(msg[1+len(fileid):], epk)

	// sign message
	sign, err := crypto.SignMessage(msg, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("CallRequestB: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	req := &protobuf.Request{
		Type: ty,
		Norf: fileid,
		Enpk: epk,
		Smsg: sign,
	}
	return proto.Marshal(req)
}

// CallRequestC returns a buffer of RequestC
func (user *GenaroUser) CallRequestC(fileid []byte, list [][]byte) ([]byte, error) {
	ty := []byte{0xc3}

	// assemble messages )
	lb := bytes.Join(list, []byte(""))

	msg := make([]byte, 1+len(fileid)+len(lb))
	copy(msg, ty)
	copy(msg[1:], fileid)
	copy(msg[1+len(fileid):], lb)

	// sign message
	sign, err := crypto.SignMessage(msg, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("CallRequestC: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	req := &protobuf.Request{
		Type: ty,
		Norf: fileid,
		List: list,
		Smsg: sign,
	}
	return proto.Marshal(req)
}

// CallRequestD returns a buffer of RequestD
func (user *GenaroUser) CallRequestD(fileid []byte) ([]byte, error) {
	ty := []byte{0xd4}

	// assemble messages )
	msg := make([]byte, 1+len(fileid))
	copy(msg, ty)
	copy(msg[1:], fileid)

	// sign message
	sign, err := crypto.SignMessage(msg, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("CallRequestD: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	req := &protobuf.Request{
		Type: ty,
		Norf: fileid,
		Smsg: sign,
	}
	return proto.Marshal(req)
}

// CallRequestE returns a buffer of RequestE
func (user *GenaroUser) CallRequestE(fileid []byte) ([]byte, error) {
	ty := []byte{0xe5}

	// assemble messages
	epk := crypto.EciesPubToBytes(&user.Epri.PublicKey, DefaultCurve)

	msg := make([]byte, 1+len(fileid)+len(epk))
	copy(msg, ty)
	copy(msg[1:], fileid)
	copy(msg[1+len(fileid):], epk)

	// sign message
	sign, err := crypto.SignMessage(msg, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("CallRequestE:  failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	req := &protobuf.Request{
		Type: ty,
		Norf: fileid,
		Enpk: epk,
		Smsg: sign,
	}
	return proto.Marshal(req)
}

// ReCallRequestA is for some special situation that client receives no response from KDC after RequestA
// Others only need to try request again
func (user *GenaroUser) ReCallRequestA(list [][]byte, path string) ([]byte, error) {
	ty := []byte{0xa1}

	// load nonce and its signature from local file
	nonce, sn, err := LoadNonce(path)
	if err != nil {
		return nil, fmt.Errorf("ReCallRequestA: failed to load nonce with error: %s", err.Error())
	}

	// assemble messages
	epk := crypto.EciesPubToBytes(&user.Epri.PublicKey, DefaultCurve)
	lb := bytes.Join(list, []byte(""))

	msg := make([]byte, 1+len(nonce)+len(sn)+len(epk)+len(lb))
	copy(msg, ty)
	copy(msg[1:], nonce)
	copy(msg[1+len(nonce):], sn)
	copy(msg[1+len(nonce)+len(sn):], epk)
	copy(msg[1+len(nonce)+len(sn)+len(epk):], lb)

	// sign message
	sign, err := crypto.SignMessage(msg, user.Spri)
	if err != nil {
		return nil, fmt.Errorf("ReCallRequestA: failed to sign message with error: %s", err.Error())
	}

	// marshal as protocol buffer
	req := &protobuf.Request{
		Type: ty,
		Norf: nonce,
		Snon: sn,
		Enpk: epk,
		List: list,
		Smsg: sign,
	}
	return proto.Marshal(req)
}

// return 8-byte random number
func getNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func checkFileIsExist(path string) bool {
	exist := true
	if _, err := os.Stat(path); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// Save nonce and its signature locally
func SaveNonce(nonce, snonce []byte, path string) (err error) {
	var f *os.File
	if checkFileIsExist(path) {
		f, _ = os.OpenFile(path, os.O_WRONLY, 0666)
	} else {
		f, _ = os.Create(path)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	n := hex.EncodeToString(nonce)
	sn := hex.EncodeToString(snonce)

	w.WriteString(n)
	w.WriteString("\n")
	w.WriteString(sn)
	return w.Flush()
}

// Load nonce and its signature from local file
func LoadNonce(path string) (nonce, snonce []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	n, _ := r.ReadString('\n')
	sn, _ := r.ReadString('\n')

	// ignore '\n'
	nonce, err = hex.DecodeString(n[:len(n)-1])
	if err != nil {
		return nil, nil, err
	}
	snonce, err = hex.DecodeString(sn)
	if err != nil {
		return nil, nil, err
	}
	return
}
