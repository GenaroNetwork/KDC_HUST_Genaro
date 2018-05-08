package client

import (
	"encoding/hex"
	"fmt"
	"genaro-crypto/crypto"
	"genaro-crypto/kdc"
	"testing"
)

var (
	responsetbuf = map[string]string{
		"responseA":      "0a01ab12c50104b2d1c88fdd46c0e496b8fb4cfafeb496de8ac102635b53c1febe2dbe2a479453cec31c3e66849b69ae55564a7db2e2d138e6d26c8def4013b4798d1b90c67dbedb49d3a5db41a3c6eccaad61c9d2095e7587434b8350262bccb0a4c0acc3a0ff1522217599fa1a5d2079e36a41a2501a342e27e99e1a2ebb17ff60e0d03c2db60946cba1abac1529a80f98e34a01d3b92c2a3c441f7d1d8f557c6345fe946fa3440ae108eb79a308243902f5a0e230b1cad6b88b7c00f3718b8ccaae3ff057b80f09932322411f1199da9e1fc3608905b94b8efddd973f14acff5f7670a5b889d4e84e26a7785e0529b0e063aeffb41c197631c3d3ef20f640f954efb0a319a105da4ac46a3301",
		"responseB":      "0a01ab12c501048ceeee586f9542d0c92dd908e395647405fa19450ce6411146437ebe35cc46fbe703b23cd26ca65d8e7d79b95b88b4c6d69ec00c7ff896b19e12b7d4a5b4df6c17325e83ff42fdf49498d9566a5166f4c4488fb4435f0025d729781761a15d1084f5b41a0343257e6dc7ea03ac96674ff2ec4a0c8a13ee8c61ef50da702d4dc3a15ffb80394b8ee97fcbf2e1dbe6cb1657915c748e435ccc97c8c35f18e5dd8a0c66f4ee64a69628c9a7a033a7789955100c58462461be714c7370d15733e55696f020092241fdbd71f2de7810b97e4153d8b7063c666587f8ebfa949f4642bf1fa3f501d6104c2a3ae96390e8d31a839292d45fbcb6a7206050de1f082685f5c10f65492a9101",
		"responseC":      "0a01cd122731206e657720707562732068617665206265656e206164646564207375636365737366756c6c7922419397ee168d931fde5f8f4f02241c2591b1b9ea63514b13c9dd153cf784f334a326d3707e938f714d47e29e1216514054621a56b8b5faf112acad7dc074b0dfee01",
		"responseE":      "0a01ef12145bf98c8eede891f1ab36a40e745f37c803ec69bc1af7010a41041bcf290fa63d7279bddb8733f4684099bb21a33af2b34234c00bf249799aebcee0a195a509379f4815d6c5e3277ab73e6987c93fb22aca808b1f70d55ed4db5c12b101043279d3a1dd58573dc064e522bb906761b014c572c5668aad869eb4948b1562252dd4dc5055b2c5911b374745b05431e4f2e52ca4b3ee74d4d2a576ef6f5597a1be0c0ce84d4bbb87456287c028f70fc8fe803474f00c626eeef92dfaf3b3a90d08821eb994fa72ca8fe88a00e1c07f89cb7e62b093504bd0368676fd6b859e38eed2e1b79fce3b55d92626e7f937a0e6e4023f4ff08123d566d06d5c67688d939cd98339b7333b207ba141fe7b0a9bd51af7010a4104ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e112b101048c12b7eb0941badf4ca187640db61865dd37c44f88409de03c3b710b49233ef0ea4fc99b2a5d232086da90109d962ab3d853ea97c38833cb9b93c31db19e46aa768661032576aa0aed9abea19e8c67c1c789ff1a1a8a9280c8882c3822805fbffe5c906ebcf561e28715fe290757fa6c01dcc35a19b5d0801b0cb5f89fecfc5969fffea7dd669777c01213e0b10d48177b809da7bbda5e6d94077e4177f37ee144aa92cf43a5b29490e94867c0c1503d22414b76d5045fdc19aa438dd76b9b05aabe8759d067f368342f1482817ea9b9f7ba67bcfa21098b13ec6c75e52bedf8ff363c01d7c390cc9d5ee15692970e65f51201",
		"responseReject": "0a010012115065726d697373696f6e2064656e6965642241c85ba845d439f0fab769edbe777b3851eca20c7db871ed1d26549cd767d7a3de6c7dd883bc821fdb73a49cc912bacc8b33a4742723ec1002ec141dd7aff8685000",
	}

	noncepath = "./testdata/nonce"

	kdcpub = "0449f0934ca944314215fc2f55ee78689b841fd605447b6e320c6dccdd537943f040dd91ee53c53aa99fc6302499825530a124c9440b46ea48bf99fc214d2d893c"
)

func TestUserInitLoadPublicKey(t *testing.T) {
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}
}

func TestEnValueEncDec(t *testing.T) {
	// generate keys
	msk := crypto.KeyGen()
	esalt := crypto.SaltGen()
	ssalt := crypto.SaltGen()
	keys := &kdc.SubKey{
		EKey: crypto.KeyDerivFunc(msk, esalt, crypto.EKeyLen),
		SKey: crypto.KeyDerivFunc(msk, ssalt, crypto.SKeyLen),
	}

	kv0 := &KeyValue{
		Key:   []byte("name"),
		Value: []byte("genaro network"),
	}

	kv1 := &KeyValue{
		Key:   []byte("pack:renderer"),
		Value: []byte("cross-env NODE_ENV=production webpack --progress --colors --config .electron-vue/webpack.renderer.config.js"),
	}

	ekv, err := EncryptKeyValue(keys, kv0)
	if err != nil {
		panic(err)
	}

	pkv, err := DecryptKeyValue(keys, ekv)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pkv.Key), string(pkv.Value))

	ekv, err = EncryptKeyValue(keys, kv1)
	if err != nil {
		panic(err)
	}

	pkv, err = DecryptKeyValue(keys, ekv)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pkv.Key), string(pkv.Value))
}

func TestGetResponseA(t *testing.T) {
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}

	kpub, _ := hex.DecodeString(kdcpub)
	pub := crypto.BytesToEcdsaPub(kpub, crypto.DefaultCurve)

	rep, _ := hex.DecodeString(responsetbuf["responseA"])
	ans, fileid, keys, err := user.GetResponseA(rep, noncepath, pub)
	if err != nil {
		panic(err)
	}

	id := hex.EncodeToString(fileid)
	ekey := hex.EncodeToString(keys.EKey)
	skey := hex.EncodeToString(keys.SKey)
	fmt.Printf("ans:%s\nfileid:%s\nekey:%s\nskey:%s\n", string(ans), id, ekey, skey)
}

func TestGetResponseB(t *testing.T) {
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaB", "./testdata/eciesB")
	if err != nil {
		panic(err)
	}

	kpub, _ := hex.DecodeString(kdcpub)
	pub := crypto.BytesToEcdsaPub(kpub, crypto.DefaultCurve)
	fileid, _ := getFileid()

	rep, _ := hex.DecodeString(responsetbuf["responseB"])
	ans, keys, err := user.GetResponseB(rep, fileid, pub)
	if err != nil {
		panic(err)
	}

	ekey := hex.EncodeToString(keys.EKey)
	skey := hex.EncodeToString(keys.SKey)
	fmt.Printf("ans:%s\nekey:%s\nskey:%s\n", string(ans), ekey, skey)
}

func TestGetResponseC(t *testing.T) {
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}

	kpub, _ := hex.DecodeString(kdcpub)
	pub := crypto.BytesToEcdsaPub(kpub, crypto.DefaultCurve)

	rep, _ := hex.DecodeString(responsetbuf["responseC"])
	ans, statue, err := user.GetResponseC(rep, pub)
	if err != nil {
		panic(err)
	}

	fmt.Printf("ans:%s\nstatue:%t", ans, statue)
}

func TestGetResponseE(t *testing.T) {
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaA", "./testdata/eciesA")
	if err != nil {
		panic(err)
	}

	kpub, _ := hex.DecodeString(kdcpub)
	pub := crypto.BytesToEcdsaPub(kpub, crypto.DefaultCurve)
	fileid, _ := getFileid()

	rep, _ := hex.DecodeString(responsetbuf["responseE"])
	ans, keys, err := user.GetResponseE(rep, fileid, pub)
	if err != nil {
		panic(err)
	}

	if ans != nil {
		fmt.Println(string(ans))
	} else {
		for _, key := range keys {
			fmt.Println(hex.EncodeToString(key.Pub))
			fmt.Println(hex.EncodeToString(key.SubKey.EKey))
			fmt.Println(hex.EncodeToString(key.SubKey.SKey))
		}
	}
}

func TestGetResponseEReject(t *testing.T) {
	user := new(GenaroUser)
	err := user.LoadAsyKey("./testdata/ecdsaIll", "./testdata/eciesIll")
	if err != nil {
		panic(err)
	}

	kpub, _ := hex.DecodeString(kdcpub)
	pub := crypto.BytesToEcdsaPub(kpub, crypto.DefaultCurve)
	fileid, _ := getFileid()

	rep, _ := hex.DecodeString(responsetbuf["responseReject"])
	ans, _, err := user.GetResponseE(rep, fileid, pub)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(ans))
}
