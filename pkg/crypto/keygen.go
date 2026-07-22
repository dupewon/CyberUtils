package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func GenerateSymmetricKey(n int) ([]byte, error) {
	key := make([]byte, n)
	_, err := rand.Read(key)
	return key, err
}

type KeyType int

const (
	KeyRSA2048 KeyType = iota
	KeyRSA4096
	KeyECDSA256
	KeyECDSA384
	KeyECDSA521
	KeyEd25519
)

func GenerateKeyPair(kt KeyType) (priv interface{}, pub interface{}, err error) {
	switch kt {
	case KeyRSA2048:
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		return k, &k.PublicKey, e
	case KeyRSA4096:
		k, e := rsa.GenerateKey(rand.Reader, 4096)
		return k, &k.PublicKey, e
	case KeyECDSA256:
		privKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return privKey, &privKey.PublicKey, e
	case KeyECDSA384:
		privKey, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return privKey, &privKey.PublicKey, e
	case KeyECDSA521:
		privKey, e := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return privKey, &privKey.PublicKey, e
	case KeyEd25519:
		pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
		return privKey, pubKey, e
	default:
		return nil, nil, ErrInvalidKeySize
	}
}
