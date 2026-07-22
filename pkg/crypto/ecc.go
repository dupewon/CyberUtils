package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
)

const (
	CurveP256 = "P256"
	CurveP384 = "P384"
	CurveP521 = "P521"
)

func GenerateECDSAKey(curve string) (*ecdsa.PrivateKey, error) {
	var c elliptic.Curve
	switch curve {
	case CurveP256:
		c = elliptic.P256()
	case CurveP384:
		c = elliptic.P384()
	case CurveP521:
		c = elliptic.P521()
	default:
		return nil, errors.New("crypto: unsupported ECDSA curve: " + curve)
	}
	return ecdsa.GenerateKey(c, rand.Reader)
}

func ECDSASign(priv *ecdsa.PrivateKey, data []byte) (r, s *big.Int, err error) {
	hash := sha256.Sum256(data)
	return ecdsa.Sign(rand.Reader, priv, hash[:])
}

func ECDSAVerify(pub *ecdsa.PublicKey, data []byte, r, s *big.Int) bool {
	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], r, s)
}

func GenerateEd25519Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

func Ed25519Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

func Ed25519Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}

func ECDSAPublicKeyToPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ECDSA PUBLIC KEY", Bytes: der}), nil
}

func ECDSAPrivateKeyToPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der}), nil
}

func ECDSAPublicKeyFromPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("crypto: failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("crypto: not an ECDSA public key")
	}
	return ecPub, nil
}

func ECDSAPrivateKeyFromPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("crypto: failed to decode PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func Ed25519PrivateKeyToPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: der}), nil
}

func Ed25519PublicKeyToPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: der}), nil
}

func Ed25519PrivateKeyFromPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("crypto: failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("crypto: not an Ed25519 private key")
	}
	return priv, nil
}

func Ed25519PublicKeyFromPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("crypto: failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("crypto: not an Ed25519 public key")
	}
	return edPub, nil
}
