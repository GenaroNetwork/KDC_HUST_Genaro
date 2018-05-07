package main

import (
	"fmt"

	"gopkg.in/mgo.v2"
)

var (
	// ACreat test file
	ACreat = "./json/initial.json"

	// This id is just used in TestCoreFunctions
	fileid = "5bf98c8eede891f1ab36a40e745f37c803ec69bc"

	AChange = "./json/modifiedbyA.json"

	BChange = "./json/modifiedbyB.json"

	CChange = "./json/modifiedbyC.json"

	AChangeA = "./json/modifiedbyAagain.json"

	keypairspath = "./keypairs"

	EkvDB = "EnKeyValues"
)

// the storage format of encrypted key-values in database
type EkeyValue struct {
	Pub, SSEKey, EKey, EValue string
}

// the format of search token
type Token struct {
	Pub, Token []byte
}

type EValues struct {
	Pub []byte
	EVs [][]byte
}

type KeyWithPub struct {
	Pub, Key0, Key1, Key2 string
}

var (
	// These keys are just used in TestCoreFunctions
	testkeys = []KeyWithPub{
		{
			// A
			"041bcf290fa63d7279bddb8733f4684099bb21a33af2b34234c00bf249799aebcee0a195a509379f4815d6c5e3277ab73e6987c93fb22aca808b1f70d55ed4db5c",
			"ed263c142a18b1c56ed667bf57adfd7a2679112707d2d5a3ebf42d8aafdf19f1",
			"8704947920ad37769deb86d2432c9765f18e138b5fdaada018a3745a7e1f8cc3",
			"aac81095a1d8496569a9f5752cfeac804ef49e70b6dbd820f2ad1edfa6603c65",
		},
		{
			// B
			"04ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e1",
			"20d05f4fb4590efc74d0e38554e8e542e25b0b646e46a0857938a6c8379af79b",
			"5abf43d212f742ff71124868b81d89596bdbf5236cecc5e4944ccef82fde2ba0",
			"5e257055d71332803e1deba2c7ee1f0f98449a8ae193e0de576fbc13d73aa318",
		},
		{
			// C
			"042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889",
			"6f77df9bc3c4be623a01879b8cf9c21ae17cc94f15634e7d997cadab60cefce0",
			"957ca0a2abea65849b73a68621d70e451c48fbfc1132354bf86fd4885b3b6e23",
			"df26744e8c45e3859b88043845fc13a79e1f4c7ffe9cb1d7e184331da61015c1",
		},
	}

	whitelist = []string{
		"04ab6d46ddeaf7e4e94adf8538c2a70644270314b11cec4d694961dea6c73d3495fce7d02b7bf4157e9a3724c8dffbd04e5d47ccac5cdc4607a9b866af2aae90e1",
		"042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889",
	}

	nwhitelist = []string{
		// D
		"048c5826fdb1f3c2f8b298bb84d8af84e422cc389ddb8d036f58ce2f21411fe3129ca16b7960109c5245733c7e651faca93b6efd78d74c699ef64ffab22ccc3394",
		// This public key has existed in whitelist
		"042cc6ca86c207d0113e49914430f8e16da5bb633afdd312f064471db1874269071df02cd7f0d819b66aeb02b1fe1b54ffc9417f98e384213ca84ad34363aae889",
	}
)

// the test key for search
var keyword = "devDependencies.new.url-loader"

func main() {

	//All test functions see test.go

	TestCoreFunctions()

	TestUploadContract()

	TestModifyContract()

	TestUpdateWhitelist()

	TestSearchContract("scripts.build:mas")

	TestDecryptContract()

	ClearCiphertextDatabase()

}

func ClearCiphertextDatabase() {
	session, err := mgo.Dial("localhost")
	if err != nil {
		fmt.Println(err)
	}
	defer session.Close()

	session.DB(EkvDB).DropDatabase()
}
