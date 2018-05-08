// Key Distribution Center (KDC) as a trusted node, is to deal with the management of keys
// The keys in kdc are used to protect the data of smart contract in genaro network. KDC
// also stores the list of superuser and access whitelist. The superusers are predetermined
// in KDC, and can obtain all the keys in kdc to access all the contract data as regulators.
// So the superuser list must be maintained very carefully. The whitelist is a list of public
// keys along with the contract fileid they can maintain.

// KDC uses MongoDB as database management system. In real-world deployment, the sensitive
// data associated with the keys is recommended to be encrypted by MongoDB.

package kdc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"genaro-crypto/crypto"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	// MskDB stores the master key of each contract file
	MskDB = "MasterKeyDB"

	// SaltDB stores the salts of each public key to generate sub keys
	// Each collection in SaltDB is named by fileid
	SaltDB = "SaltDB"

	// WilDB stores whitelist
	WilDB = "WhitelistDB"

	// SupDB stores superuser list
	SupDB = "SuperuserDB"

	// OldDB stores the outdated contract list in which the contract is completed
	// At some point, KDC will migrate expired data to genaro storage network
	// according to the fileid list in OldDB
	OldDB = "OutdatedDB"
)

var (
	// Collection in each DB
	MskCol = "masterKey"
	WilCol = "whitelist"
	SupCol = "superuser"
	OldCol = "outdatedlist"
)

var (
	ErrPubExist = fmt.Errorf("the added pub has existed in whitelist")
	ErrNoAccess = fmt.Errorf("permission denied")
	ErrNoFileid = fmt.Errorf("no such fileid in kdc")
)

type SuperUser struct {
	User string
}

type Msk struct {
	File, Key, Owner string
}

type Salt struct {
	Pub          string
	ESalt, SSalt string
}

type SubKey struct {
	EKey, SKey []byte
}

type WhiteList struct {
	File  string
	Owner string
	List  []string
}

type KeyOwner struct {
	Pub []byte
	SubKey
}

type OldList struct {
	File string
}

// SaveSuperuser saves the list of superuser who has access to all keys
func SaveSuperuser(d *mgo.Database, list [][]byte) error {
	// return superuser collection
	c := d.C(SupCol)

	for _, su := range list {
		user := hex.EncodeToString(su)

		err := c.Insert(&SuperUser{user})
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckSuperuser checks whether the user is a super user
func CheckSuperuser(d *mgo.Database, user []byte) bool {
	c := d.C(SupCol)

	u := hex.EncodeToString(user)

	result := new(SuperUser)
	err := c.Find(bson.M{"user": u}).One(result)
	if err == nil {
		return true // no err means the pub is found
	}
	return false
}

// ReturnAllKeys returns all the sub keys of the fileid for contract owner and superuser
func ReturnAllKeys(msd *mgo.Database, sud *mgo.Database,
	sad *mgo.Database, fileid, pub []byte) (ko []*KeyOwner, err error) {
	file := hex.EncodeToString(fileid)
	owner := hex.EncodeToString(pub)

	// Check whether the pub is the owner of fileid
	msc := msd.C(MskCol)
	result := new(Msk)
	msk := make([]byte, crypto.MskLen)

	err = msc.Find(bson.M{"file": file, "owner": owner}).One(result)
	if err != nil {
		// checks whether the pub is a super user
		if !CheckSuperuser(sud, pub) {
			return nil, ErrNoAccess
		}
		msk, err = GetMasterKey(msd, fileid)
		if err != nil {
			return nil, ErrNoFileid
		}
	} else {
		msk, _ = hex.DecodeString(result.Key)
	}

	// return all keys
	sac := sad.C(file)
	var salts []Salt

	err = sac.Find(bson.M{}).All(&salts)
	if err != nil {
		return nil, errors.New("ReturnAllKeys: something wrong with salts search")
	}

	for _, salt := range salts {
		esalt, ssalt := salt.toBytes()
		subk := SubKey{
			EKey: crypto.KeyDerivFunc(msk, esalt, crypto.EKeyLen),
			SKey: crypto.KeyDerivFunc(msk, ssalt, crypto.SKeyLen),
		}

		ow, _ := hex.DecodeString(salt.Pub)
		ele := &KeyOwner{
			Pub:    ow,
			SubKey: subk,
		}
		ko = append(ko, ele)
	}
	return
}

// GetMasterKey returns the master key corresponding to the input fileid
func GetMasterKey(d *mgo.Database, fileid []byte) (msk []byte, err error) {
	file := hex.EncodeToString(fileid)

	// return the named collection
	c := d.C(MskCol)
	result := new(Msk)
	err = c.Find(bson.M{"file": file}).One(result)
	if err != nil {
		return nil, err
	}

	msk, _ = hex.DecodeString(result.Key)
	return
}

// GenMasterKey generates a master key for the file
func GenMasterKey(d *mgo.Database, fileid, owner []byte) (msk []byte, err error) {
	// judge whether the msk exists already
	msk, err = GetMasterKey(d, fileid)
	if msk != nil {
		return msk, nil
	}

	// Generate 16-byte msk
	msk, err = crypto.KeyGen()
	if err != nil {
		return nil, err
	}

	file := hex.EncodeToString(fileid)
	key := hex.EncodeToString(msk)
	ow := hex.EncodeToString(owner)

	c := d.C(MskCol)

	err = c.Insert(&Msk{file, key, ow})
	if err != nil {
		return nil, err
	}
	return
}

// GetSalts returns salts according to file and public key
func GetSalts(d *mgo.Database, fileid, pub []byte) (sa *Salt, err error) {
	file := hex.EncodeToString(fileid)

	c := d.C(file)

	pk := hex.EncodeToString(pub)

	sa = new(Salt)
	err = c.Find(bson.M{"pub": pk}).One(sa)
	if err != nil {
		return nil, err
	}
	return
}

func (sa *Salt) toBytes() (esalt, ssalt []byte) {
	esalt, _ = hex.DecodeString(sa.ESalt)
	ssalt, _ = hex.DecodeString(sa.SSalt)
	return
}

func (sa *Salt) fromBytes(pub, esalt, ssalt []byte) {
	sa.Pub = hex.EncodeToString(pub)
	sa.ESalt = hex.EncodeToString(esalt)
	sa.SSalt = hex.EncodeToString(ssalt)
}

// GenSubKey generates sub keys of the file for the public key
func GenSubKey(d *mgo.Database, msk, fileid, pub []byte) (subk *SubKey, err error) {
	subk = new(SubKey)

	// judge whether the salt exists already
	sa := new(Salt)
	sa, err = GetSalts(d, fileid, pub)
	if sa != nil {
		esalt, ssalt := sa.toBytes()
		subk.EKey = crypto.KeyDerivFunc(msk, esalt, crypto.EKeyLen)
		subk.SKey = crypto.KeyDerivFunc(msk, ssalt, crypto.SKeyLen)
		return
	}

	// generate salts
	esalt, err := crypto.GetSalt()
	if err != nil {
		return nil, errors.New("GenSubKey: failed to get esalt")
	}
	ssalt, err := crypto.GetSalt()
	if err != nil {
		return nil, errors.New("GenSubKey: failed to get ssalt")
	}

	nsa := new(Salt)
	nsa.fromBytes(pub, esalt, ssalt)

	file := hex.EncodeToString(fileid)

	// save salts
	c := d.C(file)
	err = c.Insert(nsa)
	if err != nil {
		return nil, err
	}

	// generate sub keys
	subk.EKey = crypto.KeyDerivFunc(msk, esalt, crypto.EKeyLen)
	subk.SKey = crypto.KeyDerivFunc(msk, ssalt, crypto.SKeyLen)
	return
}

// SaveWhitelist saves whitelist into database
func SaveWhitelist(d *mgo.Database, fileid, owner []byte, list [][]byte) error {
	file := hex.EncodeToString(fileid)
	ow := hex.EncodeToString(owner)

	var wil []string
	for _, pub := range list {
		wil = append(wil, hex.EncodeToString(pub))
	}

	// return whitelist collection
	c := d.C(WilCol)

	err := c.Insert(&WhiteList{file, ow, wil})
	if err != nil {
		return err
	}
	return nil
}

// CheckWhitelist checks whether the public key is the owner of the file or in the whitelist
func CheckWhitelist(d *mgo.Database, fileid, pub []byte) bool {
	file := hex.EncodeToString(fileid)
	sn := hex.EncodeToString(pub)
	result := new(WhiteList)

	// return whitelist collection
	c := d.C(WilCol)
	err := c.Find(bson.M{"$or": []bson.M{{"file": file, "list": sn},
		{"file": file, "owner": sn}}}).One(&result)
	if err == nil {
		return true // no err means the pub is found
	}
	return false
}

// UpdateWhitelist adds new public key into whitelist
func UpdateWhitelist(c *mgo.Collection, fileid, pub []byte) error {

	file := hex.EncodeToString(fileid)
	sn := hex.EncodeToString(pub)
	result := new(WhiteList)

	err := c.Find(bson.M{"file": file, "list": sn}).One(&result)
	if err == nil {
		return ErrPubExist // has existed
	}

	err = c.Update(bson.M{"file": file},
		bson.M{"$push": bson.M{
			"list": sn,
		}})
	if err != nil {
		return err
	}
	return nil
}

// AddOldList adds the fileid of expired contract into old list
func AddOldList(d *mgo.Database, fileid []byte) error {

	c := d.C(OldCol)
	f := hex.EncodeToString(fileid)

	result := new(OldList)

	err := c.Find(bson.M{"file": f}).One(&result)
	if err == nil {
		return nil
	}

	err = c.Insert(&OldList{f})
	if err != nil {
		return err
	}
	return nil
}
