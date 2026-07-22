package hash

import (
	"crypto/hmac"
	sha256std "crypto/sha256"
	sha512std "crypto/sha512"
	"encoding/hex"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

func SHA256(data []byte) string {
	h := sha256std.Sum256(data)
	return hex.EncodeToString(h[:])
}

func SHA512(data []byte) string {
	h := sha512std.Sum512(data)
	return hex.EncodeToString(h[:])
}

func SHA3_256(data []byte) string {
	h := sha3.New256()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func SHA3_512(data []byte) string {
	h := sha3.New512()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func BLAKE2b_256(data []byte) string {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("hash: blake2b-256 init failed: " + err.Error())
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func BLAKE2b_512(data []byte) string {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic("hash: blake2b-512 init failed: " + err.Error())
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func HMACSHA256(key, data []byte) string {
	mac := hmac.New(sha256std.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func HMACSHA512(key, data []byte) string {
	mac := hmac.New(sha512std.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func CompareHash(hashFn func([]byte) string, data []byte, encodedHash string) bool {
	return hmac.Equal([]byte(hashFn(data)), []byte(encodedHash))
}

func TimingSafeCompare(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func HashReader(r io.Reader, hf func() hash.Hash) (string, error) {
	h := hf()
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
