package protocrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"io"
)

func generateNonce(gcm cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

func decryptField(src protoField, gcm cipher.AEAD) (dst protoField, err error) {
	encField := &EncryptedField{}
	err = proto.Unmarshal(src.FieldContent, encField)
	if err != nil {
		return dst, err
	}

	decData, err := gcm.Open(nil, encField.GetNonce(), encField.GetContent(), nil)
	if err != nil {
		return dst, err
	}

	return protoField{
		FieldNumber:  src.FieldNumber,
		FieldType:    uint(encField.GetOriginalType()),
		FieldContent: decData,
	}, nil
}

func encryptField(src protoField, gcm cipher.AEAD) (dst protoField, err error) {
	nonce, err := generateNonce(gcm)
	if err != nil {
		return dst, err
	}

	encData := gcm.Seal(nil, nonce, src.FieldContent, nil)

	encField := &EncryptedField{
		OriginalType: uint32(src.FieldType),
		Nonce:        nonce,
		Content:      encData,
	}

	encDataBytes, _ := proto.Marshal(encField)

	return protoField{
		FieldNumber:  src.FieldNumber,
		FieldType:    proto.WireBytes,
		FieldContent: encDataBytes,
	}, nil
}

func buildUVarint(v uint64) []byte {
	data := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(data, v)
	data = data[:n]

	return data
}

// GenerateKey generates a cryptographically secure AES-GCM Key (32 bytes)
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	// populates our key with a cryptographically secure
	// random sequence
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}
