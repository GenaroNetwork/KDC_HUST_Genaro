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
		"responseA":      "0a01ab12e50104979010b029bcf0d1543b9f561bde65737f46538afb4c18eede6f6d6e86ee819818f9d29a991b362698f337f994e31ed45622330c1ac83f285face19fc3d61bf933366c9e31499e15d91a492e0561cab409bd5197a2915a1873e1beeba1ce7ca1e1c67aa5eb4d3a425fd52beff565ac60d4eee0d3687f94b13211b847396cd5e16dbed6dbc4e0e533876692f1886b3d74812d798925bd7ed52c09f081c8cfbb4b8fc221d5585dcb5958d0979c7ed1fec2245fbe3e7023a4788f1e627e03eb0ec0b0b7338402d6fae3cdfd6be3bab04b1ca83f25c6d1842dfc58e65f30e320eed438c814c02241b25c599267acf98684966eadccb050f195ce89f97eb4aef753f11c256f8e428f54cd589b8318499ea450d47a0b9396f3939ebaf3fea0eae33566f31600aa785000",
		"responseB":      "0a01ab12e501040b0c6fa16c753846ac5b6b6eca585e6940441bcb27672f0666414c1caf9dbbddf7d0b9a793d4fa52edc638564304215daebd18880ce6484bbbbb7cbace38410fe4058b059734a4633a45e37dac3e2bff6ead3fff3e5b4f8df0b2a8ff829157e8f26ece66d57f9c8c436ce344c6f1e7babb29441d2b5a2b8fa23e214df344ad4d784edc5afd914d9b3246eb8ad6b24c7c0b9504612209ec57f1a8c0e664e4882ddc483d06e767e455f602fc36f32e801c8239c04d77479f80f6853dfa8f9519212f602e48519f337c81b40f00d0ac75f60de2c4a5c2a9dc761ae2c8a5c772af03355874cf224173c0aef67a86bafdcc6f67fab963de2193d9086631f979c99518e9dae6a56700502fe2cb89826a682b0a777e708236d1d8cdc65b0b6ce2f9f98497b205281b5a01",
		"responseC":      "0a01cd122731206e657720707562732068617665206265656e206164646564207375636365737366756c6c7922419397ee168d931fde5f8f4f02241c2591b1b9ea63514b13c9dd153cf784f334a326d3707e938f714d47e29e1216514054621a56b8b5faf112acad7dc074b0dfee01",
		"responseE":      "0a01ef12145bf98c8eede891f1ab36a40e745f37c803ec69bc1a97020a41041bcf290fa63d7279bddb8733f4684099bb21a33af2b34234c00bf249799aebcee0a195a509379f4815d6c5e3277ab73e6987c93fb22aca808b1f70d55ed4db5c12d101043b8837c5f5bd72a5476871b1421d5a68e802f5f92aff65d8d92fcaba83dbeb9eaa69360c3a954e824a00fa639430a073c5610e85b17230a010f4a4856f28cb3bb529a6182d596ab374e15381ed0bdaba6cfad6d352116df433dddb6d0919731e29bbe0d4b337981f47f179d2f996231de609ddca47d429bfb06931b8f8e4b2d1763abbb4e1c536f16a2410b21b0ef46b5a1d97d0ac6d087ef6571cd05c98c5058ebb8d793090de4d0fd8cc220c0104ffa5c22643ade8a692686d8b3aac49af3cd16b78aa11cccbdff4632d74a632b7cb1a97020a4104ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e112d10104aee4f5c59a6759086b7ee9f96e620442f081c56e6c7da48485ddf870dffec3890a262073f7f68947b872c29c0afbde24a5a7327c10ebc656d96a325115f9684036f17aab00a13374b29faf998bc5ea9b403ed9e969b5005fc5d30c316a91bcc4fde8240fcce6f4556c8436b3ec813fa908697eda5df7e164ac8821a0d7cdf39e9b6bb8ea6bcf24ca884d4b4d686e8a3b64407fad34cd5d1f74edb1ac43dddccdb8807b018dee69f0db652fa7d3f5d2e860def6dd57f86b5bdf48ab674d9ce557a5ffb9a085742ce354fbade85b96bcb02241abbdb9701a3964193f071a18e4307fb3f3c2b46bd29c5fd2e4bf61f18d27db170ea277e08006ddf57c16b1255a26c7c81f592ceca140d3248c2c7bfe6ba4300401",
		"responseReject": "0a010012125065726d697373696f6e2064656e696564212241ccc5c65d4ac7b7215acceb4cc6b7f63489dab27862e9aedd1763b4d071105bd517d487203792c68b7a7f16102a1af71018aefd93b5da2d86e9963717c0edb18f01",
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

func TestEVEncDEC(t *testing.T) {
	// generate keys
	msk, err := crypto.KeyGen()
	if err != nil {
		panic(err)
	}
	salt0, err := crypto.GetSalt()
	if err != nil {
		panic(err)
	}
	salt1, err := crypto.GetSalt()
	if err != nil {
		panic(err)
	}
	salt2, err := crypto.GetSalt()
	if err != nil {
		panic(err)
	}
	keys := &kdc.SubKey{
		Subk0: crypto.KeyDerivFunc(msk, salt0),
		Subk1: crypto.KeyDerivFunc(msk, salt1),
		Subk2: crypto.KeyDerivFunc(msk, salt2),
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
	key0 := hex.EncodeToString(keys.Subk0)
	key1 := hex.EncodeToString(keys.Subk1)
	key2 := hex.EncodeToString(keys.Subk2)
	fmt.Printf("ans:%s\nfileid:%s\nkey0:%s\nkey1:%s\nkey2:%s\n", string(ans), id, key0, key1, key2)
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

	key0 := hex.EncodeToString(keys.Subk0)
	key1 := hex.EncodeToString(keys.Subk1)
	key2 := hex.EncodeToString(keys.Subk2)
	fmt.Printf("ans:%s\nkey0:%s\nkey1:%s\nkey2:%s\n", string(ans), key0, key1, key2)
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
			fmt.Println(hex.EncodeToString(key.SubKey.Subk0))
			fmt.Println(hex.EncodeToString(key.SubKey.Subk1))
			fmt.Println(hex.EncodeToString(key.SubKey.Subk2))
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
