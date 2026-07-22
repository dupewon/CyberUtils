package crypto

import (
	"encoding/pem"
	"errors"
)

func PEMEncode(blockType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
}

func PEMDecode(data []byte) (blockType string, raw []byte, err error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return "", nil, errors.New("crypto: failed to decode PEM data")
	}
	if len(rest) > 0 {
		return "", nil, errors.New("crypto: trailing data after PEM block")
	}
	return block.Type, block.Bytes, nil
}
