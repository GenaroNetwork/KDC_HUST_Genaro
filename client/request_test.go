package client

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"genaro-crypto/crypto"
	"genaro-crypto/protobuf"
	"github.com/golang/protobuf/proto"
	"testing"
)

var (
	whitelist = []string{
		"04ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e1",
		"042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889",
	}

	nwhitelist = []string{
		"048c5826fdb1f3c2f8b298bb84d8af84e422cc389ddb8d036f58ce2f21411fe3129ca16b7960109c5245733c7e651faca93b6efd78d74c699ef64ffab22ccc3394",
		// This public key has existed in whitelist
		"042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889",
	}
)

func getFileid() ([]byte, error) {
	_, sn, err := LoadNonce(noncepath)
	if err != nil {
		return nil, err
	}

	fileid := crypto.SHA1(sn)
	return fileid[:], nil
}

func TestCallRequestAAndReCall(t *testing.T) {
	// initialize user
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
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
		fmt.Println("This test failed!")
	}

	// print protocol buffer
	pb := &protobuf.Request{}
	err = proto.Unmarshal(buf, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(pb)
}

func TestCallRequestB(t *testing.T) {
	fileid, err := getFileid()
	if err != nil {
		panic(err)
	}

	user := new(GenaroUser)
	err = user.LoadAsyKey("./testdata/ecdsaB", "./testdata/eciesB")
	if err != nil {
		panic(err)
	}

	buf, err := user.CallRequestB(fileid)
	if err != nil {
		panic(err)
	}

	pb := &protobuf.Request{}
	err = proto.Unmarshal(buf, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(pb)

}

func TestCallRequestC(t *testing.T) {
	fileid, err := getFileid()
	if err != nil {
		panic(err)
	}

	user := new(GenaroUser)
	err = user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}

	var nlist [][]byte
	for _, pub := range nwhitelist {
		p, _ := hex.DecodeString(pub)
		nlist = append(nlist, p)
	}

	buf, err := user.CallRequestC(fileid, nlist)
	if err != nil {
		panic(err)
	}

	pb := &protobuf.Request{}
	err = proto.Unmarshal(buf, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(pb)
}

func TestCallRequestD(t *testing.T) {
	fileid, err := getFileid()
	if err != nil {
		panic(err)
	}

	user := new(GenaroUser)
	err = user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}

	buf, err := user.CallRequestD(fileid)
	if err != nil {
		panic(err)
	}

	pb := &protobuf.Request{}
	err = proto.Unmarshal(buf, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(pb)
}

func TestCallRequestE(t *testing.T) {
	fileid, err := getFileid()
	if err != nil {
		panic(err)
	}

	user := new(GenaroUser)
	err = user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}

	buf, err := user.CallRequestE(fileid)
	if err != nil {
		panic(err)
	}

	pb := &protobuf.Request{}
	err = proto.Unmarshal(buf, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(pb)
}

func TestPrintRequestBuffer(t *testing.T) {
	usera := new(GenaroUser)
	err := usera.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}
	userb := new(GenaroUser)
	err = userb.LoadAsyKey("./testdata/ecdsaB", "./testdata/eciesB")
	if err != nil {
		panic(err)
	}
	illegal := new(GenaroUser)
	err = illegal.LoadAsyKey("./testdata/ecdsaIll", "./testdata/eciesIll")
	if err != nil {
		panic(err)
	}

	fileid, err := getFileid()
	if err != nil {
		panic(err)
	}

	var list [][]byte
	for _, pub := range whitelist {
		p, _ := hex.DecodeString(pub)
		list = append(list, p)
	}

	var nlist [][]byte
	for _, pub := range nwhitelist {
		p, _ := hex.DecodeString(pub)
		nlist = append(nlist, p)
	}

	buf, err := usera.ReCallRequestA(list, noncepath)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = userb.CallRequestB(fileid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = usera.CallRequestC(fileid, nlist)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = usera.CallRequestD(fileid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = usera.CallRequestE(fileid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = illegal.CallRequestB(fileid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = illegal.CallRequestC(fileid, nlist)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = illegal.CallRequestD(fileid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	buf, err = illegal.CallRequestE(fileid)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(buf))
}