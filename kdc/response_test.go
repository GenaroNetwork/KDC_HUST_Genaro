package kdc

import (
	"encoding/hex"
	"fmt"
	"genaro-crypto/crypto"
	"genaro-crypto/protobuf"
	"github.com/golang/protobuf/proto"
	"gopkg.in/mgo.v2"
	"testing"
)

var (
	requestbuf = map[string]string{
		"requestA": "0a01a11208d04e7ad983557d961a4169384d1ded73864e0de723c4af07278190825d3ad0848bc6500fb78fbd5b11ea47e76f1b7836327af22a03b37632cc16c4ddf728e90f4df3072cce8a6ce1f9c5002241048cb0defe41ba8a740e5236a99f537192547da3fea9147aa1f1fee16328c2d8c19b2ad241e9d7f423a757c859451cb54ea58b75793f50fd8a17a29b5f670b28dc2a4104ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e12a41042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae8893241873731cf5b172fa0fa7ff44884852a6ce8aa628ec55b7253eb2d045eaf6b9ae529d7b5a86dcb47c92dc62ec52a9cf698e841cc5b550d4d6f38acc037a60042e901",
		"requestB": "0a01b212145bf98c8eede891f1ab36a40e745f37c803ec69bc224104bdf5ae8618fa5e93384f632bb2a98a66140815e85b921ea371490c350260b61362155102fe1216a4e7c6e11437570acdbf528571d1b18d20a882c2825e1e57c4324163ef95f24c968f2e30e2688cb7aba06b42eb4484d255197d4e0db7073cb11b884925d1e6823e9d3a438261060fc913ae63df10bd09271785323ac7b35747317e01",
		"requestC": "0a01c312145bf98c8eede891f1ab36a40e745f37c803ec69bc2a41048c5826fdb1f3c2f8b298bb84d8af84e422cc389ddb8d036f58ce2f21411fe3129ca16b7960109c5245733c7e651faca93b6efd78d74c699ef64ffab22ccc33942a41042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae8893241364e8c542a72d47fecc815d048625446bf5acda980b8d63fb9dd3d10c89a16275bfdacca57425060f0a7de669e4abe294ea2ef32988dc52d6532cf4ebbbc4c2e00",
		"requestD": "0a01d412145bf98c8eede891f1ab36a40e745f37c803ec69bc3241b303f3ab57ba231f1edda99c633a7722f62685051d0f0310ca4771ec9223deb775ef7c1eb5340465afa6497500fd96c3a9f82b8e98b70be18f80fb1120795d5a00",
		"requestE": "0a01e512145bf98c8eede891f1ab36a40e745f37c803ec69bc2241048cb0defe41ba8a740e5236a99f537192547da3fea9147aa1f1fee16328c2d8c19b2ad241e9d7f423a757c859451cb54ea58b75793f50fd8a17a29b5f670b28dc3241714cf7f51d0e3cba5588ffc4150195e3d4158b4b6ba868219c3d5f481480d0934a8019c2462ba86413960f6ad7502df6f3e67d2580b24ab6cf8d55ac2e4d1fd601",
		"illgreqB": "0a01b212145bf98c8eede891f1ab36a40e745f37c803ec69bc224104d34dba2765b15eb6c58618adcbf8d2cdc3e27071d132473ac7473f5cc3c1662f8db95a0983157c237d9c01d65fab84858363804fa5f1a9b60764c02db706254b3241ff7c63ee0972ac95813e7eacdf7a0259e9c9b16f540df8a5680edd6626d87032446ec53d30df964a8e62b577e17e37c3c875cd65d6894ef848a4ddcbb40635e600",
		"illgreqC": "0a01c312145bf98c8eede891f1ab36a40e745f37c803ec69bc2a41048c5826fdb1f3c2f8b298bb84d8af84e422cc389ddb8d036f58ce2f21411fe3129ca16b7960109c5245733c7e651faca93b6efd78d74c699ef64ffab22ccc33942a41042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889324171bdeeef6484980308c2f0da4b34971bcc710d1ce2cf0e31b98617bca5212cd2589988b67a634ea1dbca20cbedf7377cf5bb9a5f7335e7b161a9e4a9ac893bc601",
		"illgreqD": "0a01d412145bf98c8eede891f1ab36a40e745f37c803ec69bc3241721d5d12ebc881e10f5ceac74f107c47088755b7f49e5e7c622c37604145567e37a424dc933b7713521e1967eb3428db33cfa87fe36479b50ba1d2e9f66632a701",
		"illgreqE": "0a01e512145bf98c8eede891f1ab36a40e745f37c803ec69bc224104d34dba2765b15eb6c58618adcbf8d2cdc3e27071d132473ac7473f5cc3c1662f8db95a0983157c237d9c01d65fab84858363804fa5f1a9b60764c02db706254b324158ac70e1b7149ad4ae7220b53a95f3b8e1276a31f308982f1c79010a4d3ad0db7cd64f5264d0ec8046452a4ee933f08c2de6e48292058abae1653a73dc5dd92501",
	}

	ecdsakdc = "ecdsakdc"
)

func TestResopndToRequestA(t *testing.T) {
	kpri, err := crypto.LoadEcdsaKeyFromFile(ecdsakdc)
	if err != nil {
		panic(err)
	}

	req, _ := hex.DecodeString(requestbuf["requestA"])
	rep, err := ResopndToRequest(req, kpri)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(rep))
}

func TestResopndToRequestB(t *testing.T) {
	kpri, err := crypto.LoadEcdsaKeyFromFile(ecdsakdc)
	if err != nil {
		panic(err)
	}

	req, _ := hex.DecodeString(requestbuf["requestB"])
	rep, err := ResopndToRequest(req, kpri)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(rep))

	ireq, _ := hex.DecodeString(requestbuf["illgreqB"])
	irep, err := ResopndToRequest(ireq, kpri)
	if err != nil {
		panic(err)
	}
	pb := &protobuf.Response{}
	err = proto.Unmarshal(irep, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pb.Cora))

}

func TestResopndToRequestC(t *testing.T) {
	kpri, err := crypto.LoadEcdsaKeyFromFile(ecdsakdc)
	if err != nil {
		panic(err)
	}

	req, _ := hex.DecodeString(requestbuf["requestC"])
	rep, err := ResopndToRequest(req, kpri)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(rep))
	pb := &protobuf.Response{}
	err = proto.Unmarshal(rep, pb)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pb.Cora))

	ireq, _ := hex.DecodeString(requestbuf["illgreqC"])
	irep, err := ResopndToRequest(ireq, kpri)
	if err != nil {
		panic(err)
	}
	ipb := &protobuf.Response{}
	err = proto.Unmarshal(irep, ipb)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(ipb.Cora))

}

// no response for RequestD
func TestResopndToRequestD(t *testing.T) {
	kpri, err := crypto.LoadEcdsaKeyFromFile(ecdsakdc)
	if err != nil {
		panic(err)
	}

	req, _ := hex.DecodeString(requestbuf["requestD"])
	_, err = ResopndToRequest(req, kpri)
	if err != nil {
		panic(err)
	}

	ireq, _ := hex.DecodeString(requestbuf["illgreqD"])
	_, err = ResopndToRequest(ireq, kpri)
	if err != nil {
		panic(err)
	}
}

func TestResopndToRequestE(t *testing.T) {
	kpri, err := crypto.LoadEcdsaKeyFromFile(ecdsakdc)
	if err != nil {
		panic(err)
	}

	req, _ := hex.DecodeString(requestbuf["requestE"])
	rep, err := ResopndToRequest(req, kpri)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(rep))

	ireq, _ := hex.DecodeString(requestbuf["illgreqC"])
	irep, err := ResopndToRequest(ireq, kpri)
	if err != nil {
		panic(err)
	}
	ipb := &protobuf.Response{}
	err = proto.Unmarshal(irep, ipb)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(ipb.Cora))
}

func TestPrintResponse(t *testing.T) {
	kpri, err := crypto.LoadEcdsaKeyFromFile(ecdsakdc)
	if err != nil {
		panic(err)
	}

	req, _ := hex.DecodeString(requestbuf["requestA"])
	rep, err := ResopndToRequest(req, kpri)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(rep))

	req, _ = hex.DecodeString(requestbuf["requestB"])
	rep, err = ResopndToRequest(req, kpri)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(rep))

	req, _ = hex.DecodeString(requestbuf["requestC"])
	rep, err = ResopndToRequest(req, kpri)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(rep))

	// no response
	req, _ = hex.DecodeString(requestbuf["requestD"])
	rep, err = ResopndToRequest(req, kpri)
	if err != nil {
		fmt.Println(err)
	}

	req, _ = hex.DecodeString(requestbuf["requestE"])
	rep, err = ResopndToRequest(req, kpri)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(rep))

	req, _ = hex.DecodeString(requestbuf["illgreqE"])
	rep, err = ResopndToRequest(req, kpri)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(rep))
}

func TestDeleteDB(t *testing.T) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		fmt.Println("failed to connect with local host")
	}
	defer session.Close()

	msd := session.DB(MskDB)
	err = msd.DropDatabase()
	if err != nil {
		fmt.Println(err)
	}

	sad := session.DB(SaltDB)
	err = sad.DropDatabase()
	if err != nil {
		fmt.Println(err)
	}

	wid := session.DB(WilDB)
	err = wid.DropDatabase()
	if err != nil {
		fmt.Println(err)
	}

	sud := session.DB(SupDB)
	err = sud.DropDatabase()
	if err != nil {
		fmt.Println(err)
	}

	old := session.DB(OldDB)
	err = old.DropDatabase()
	if err != nil {
		fmt.Println(err)
	}
}