// This is a public key cryptosystem including an ecies encrypt-decrypt scheme,
// an ecdsa sign-Verify scheme, and the management of public-private key pairs
// the ecdsa key is used to sign message and is also the identity of genaro user
// The ecies key is used to encrypt communications

// The two kinds of keys will be stored locally
// ecies should be updated termly

package crypto

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// KeyPairs is the character encoding form of public-private key pairs
type KeyPairs struct {
	Pk []byte
	Sk []byte
}

// Our Ecies scheme forks ethereum/go-ethereum/crypto which only supports S256() and P256() temporarily
var DefaultCurve = ethcrypto.S256()

// EciesEncrypt encrypts message by ecies scheme
func EciesEncrypt(rand io.Reader, pub *ecies.PublicKey, msg []byte) (cipher []byte, err error) {
	cipher, err = ecies.Encrypt(rand, pub, msg, nil, nil)
	if err != nil {
		return nil, err
	}
	return
}

// EciesDecrypt decrypts the ecies ciphertext to get message
func EciesDecrypt(cipher []byte, pri *ecies.PrivateKey) (msg []byte, err error) {
	msg, err = pri.Decrypt(cipher, nil, nil)
	if err != nil {
		return nil, err
	}
	return
}

// SignMessage signs message using secp256k1 algorithm
func SignMessage(msg []byte, pri *ecdsa.PrivateKey) ([]byte, error) {
	// hash msg by sha3-256
	hash := SHA3_256(msg)

	return ethcrypto.Sign(hash, pri)
}

// PubFromSign recovers public key from signature
func PubFromSign(msg, sign []byte) ([]byte, error) {
	// hash msg
	hash := SHA3_256(msg)

	return ethcrypto.Ecrecover(hash, sign)
}

// VerifySignature verifies the signature with given public key
// This is used to verify the signature of someone like KDC whose public key is well-known
func VerifySignature(msg, sign []byte, pub *ecdsa.PublicKey) bool {
	//hash msg
	hash := SHA3_256(msg)

	// recovery public key from signature
	rpub, err := PubFromSign(msg, sign)
	if err != nil {
		return false
	}

	bpub := EcdsaPubToBytes(pub, DefaultCurve)
	if !bytes.Equal(rpub, bpub) {
		return false
	}

	// Verify Signature
	if !ethcrypto.VerifySignature(bpub, hash, sign[:len(sign)-1]) {
		return false
	}
	return true
}

// VerifySignNoPub verifies the signature without public key
// This is used to verify the signature of genaro nodes
func VerifySignNoPub(msg, sign []byte) bool {
	//hash msg
	hash := SHA3_256(msg)

	// recovery public key from signature
	rpub, err := PubFromSign(msg, sign)
	if err != nil {
		return false
	}

	// Verify Signature
	if !ethcrypto.VerifySignature(rpub, hash, sign[:len(sign)-1]) {
		return false
	}
	return true
}

// GenerateEcdsaPri generates an ecdsa private key
func GenerateEcdsaPri(rand io.Reader, curve elliptic.Curve) (pri *ecdsa.PrivateKey, err error) {
	pri, err = ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return
}

// GenerateEciesPri generates an ECIES private key
func GenerateEciesPri(rand io.Reader, curve elliptic.Curve) (pri *ecies.PrivateKey, err error) {
	params := ecies.ParamsFromCurve(curve)
	pri, err = ecies.GenerateKey(rand, curve, params)
	if err != nil {
		return nil, err
	}
	return
}

// BytesToEciesPub transforms bytes to an ecies public key
func BytesToEciesPub(pk []byte, curve elliptic.Curve) *ecies.PublicKey {
	spub := BytesToEcdsaPub(pk, curve)
	return ecies.ImportECDSAPublic(spub)
}

// EciesPubToBytes transforms an ecies public key to bytes
func EciesPubToBytes(pub *ecies.PublicKey, curve elliptic.Curve) []byte {
	spub := pub.ExportECDSA()
	return EcdsaPubToBytes(spub, curve)
}

func BytesToEcdsaPub(pub []byte, curve elliptic.Curve) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	x, y := elliptic.Unmarshal(curve, pub)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func EcdsaPubToBytes(pub *ecdsa.PublicKey, curve elliptic.Curve) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(curve, pub.X, pub.Y)
}

// create a private key with the given D value
func bytesToEcdsaPri(d []byte, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	pri := new(ecdsa.PrivateKey)
	pri.PublicKey.Curve = curve
	if 8*len(d) != pri.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", pri.Params().BitSize)
	}
	pri.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if pri.D.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if pri.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}

	pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(d)
	if pri.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return pri, nil
}

// export a private key into a binary dump
func ecdsaPriToBytes(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func cmpPublic(pub1, pub2 *ecdsa.PublicKey) bool {
	if pub1.X == nil || pub1.Y == nil {
		return false
	}
	if pub2.X == nil || pub2.Y == nil {
		return false
	}
	pub1Out := elliptic.Marshal(pub1.Curve, pub1.X, pub1.Y)
	pub2Out := elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)
	return bytes.Equal(pub1Out, pub2Out)
}

func cmpEcdsaPrivate(prv1, prv2 *ecdsa.PrivateKey) bool {
	if prv1 == nil || prv1.D == nil {
		return false
	} else if prv2 == nil || prv2.D == nil {
		return false
	} else if prv1.D.Cmp(prv2.D) != 0 {
		return false
	} else {
		return cmpPublic(&prv1.PublicKey, &prv2.PublicKey)
	}
}

func cmpEciesPrivate(prv1, prv2 *ecies.PrivateKey) bool {
	p1 := prv1.ExportECDSA()
	p2 := prv2.ExportECDSA()
	return cmpEcdsaPrivate(p1, p2)
}

// EcdsaKeyToBytes transforms ecdsa key pairs to bytes pairs
func (kp *KeyPairs) EcdsaKeyToBytes(pri *ecdsa.PrivateKey, curve elliptic.Curve) error {
	kp.Pk = EcdsaPubToBytes(&pri.PublicKey, curve)
	kp.Sk = ecdsaPriToBytes(pri)
	if kp.Pk == nil || kp.Sk == nil {
		return errors.New("EcdsaKeyToBytes: failed to transform ecdsa key to bytes")
	}
	return nil
}

// EciesKeyToBytes transforms ecies key pairs to bytes pairs
func (kp *KeyPairs) EciesKeyToBytes(pri *ecies.PrivateKey, curve elliptic.Curve) error {
	spri := pri.ExportECDSA()
	err := kp.EcdsaKeyToBytes(spri, curve)
	if err != nil {
		return err
	}
	return nil
}

// BytesToEcdsaKey transforms bytes pairs to ecdsa key pairs
func BytesToEcdsaKey(pk, sk []byte, curve elliptic.Curve) (pri *ecdsa.PrivateKey, err error) {
	pub := BytesToEcdsaPub(pk, curve)
	pri, err = bytesToEcdsaPri(sk, curve)
	if err != nil || !cmpPublic(pub, &pri.PublicKey) {
		return nil, errors.New("BytesToEcdsaKey: wrong key paris")
	}
	return
}

// BytesToEciesKey transforms bytes pairs to ecies key pairs
func BytesToEciesKey(pk, sk []byte, curve elliptic.Curve) (pri *ecies.PrivateKey, err error) {
	spri, err := BytesToEcdsaKey(pk, sk, curve)
	if err != nil {
		return nil, err
	}
	return ecies.ImportECDSA(spri), nil
}

func checkFileIsExist(path string) bool {
	exist := true
	if _, err := os.Stat(path); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// SaveKeyToFile saves bytes key pairs to file
func (kp *KeyPairs) SaveKeyToFile(path string) error {
	var f *os.File
	if checkFileIsExist(path) {
		f, _ = os.OpenFile(path, os.O_WRONLY, 0666)
	} else {
		f, _ = os.Create(path)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	pk := hex.EncodeToString(kp.Pk)
	sk := hex.EncodeToString(kp.Sk)

	w.WriteString(pk)
	w.WriteString("\n")
	w.WriteString(sk)

	return w.Flush()
}

// LoadEcdsaKeyFromFile loads ecdsa key pairs from file
func LoadEcdsaKeyFromFile(path string) (pri *ecdsa.PrivateKey, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	p, _ := r.ReadString('\n')
	s, _ := r.ReadString('\n')

	// ignore '\n'
	pk, err := hex.DecodeString(p[:len(p)-1])
	if err != nil {
		return nil, err
	}
	sk, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	pri, err = BytesToEcdsaKey(pk, sk, DefaultCurve)
	if err != nil {
		return nil, err
	}
	return
}

// LoadEciesKeyFromFile loads ecies key pairs from file
func LoadEciesKeyFromFile(path string) (pri *ecies.PrivateKey, err error) {
	spri, err := LoadEcdsaKeyFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("LoadEciesKeyFromFile: failed to load key with error: %s", err.Error())
	}
	return ecies.ImportECDSA(spri), nil
}

// UpdateEciesKey updets an ecies key pair into the given file
func UpdateEciesKey(path string, rand io.Reader, curve elliptic.Curve) error {
	pri, err := GenerateEciesPri(rand, curve)
	if err != nil {
		return err
	}
	kp := new(KeyPairs)
	err = kp.EciesKeyToBytes(pri, curve)
	if err != nil {
		return errors.New("UpdateEciesKey: failed to transform ecies key to bytes")
	}

	err = kp.SaveKeyToFile(path)
	if err != nil {
		return errors.New("UpdateEciesKey: failed to save key to file")
	}
	return nil
}
