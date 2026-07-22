package otp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

const recoveryCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func GenerateBackupCodes(count, codeLength int) ([]string, error) {
	codes := make([]string, count)
	for i := range codes {
		code, err := generateRecoveryCode(codeLength)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func GenerateRecoveryCode(length int) (string, error) {
	return generateRecoveryCode(length)
}

func ValidateRecoveryCode(codes []string, input string) (bool, []string) {
	for i, code := range codes {
		if code == input {
			return true, append(codes[:i], codes[i+1:]...)
		}
	}
	return false, codes
}

func generateRecoveryCode(length int) (string, error) {
	if length <= 0 {
		length = 8
	}
	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(recoveryCharset))))
		if err != nil {
			return "", err
		}
		code[i] = recoveryCharset[n.Int64()]
	}
	if len(code) > 4 {
		return string(code[:len(code)/2]) + "-" + string(code[len(code)/2:]), nil
	}
	return string(code), nil
}

func GenerateHexRecoveryCode(bytes int) (string, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func FormatBackupCodes(codes []string) string {
	var result string
	for i, code := range codes {
		result += fmt.Sprintf("%2d: %s\n", i+1, code)
	}
	return result
}
