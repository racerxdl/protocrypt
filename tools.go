package protocrypt

import (
	"crypto/cipher"
	"crypto/rand"
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

	decData, err := gcm.Open(nil, encField.Nonce, encField.Content, nil)
	if err != nil {
		return dst, err
	}

	return protoField{
		FieldNumber:  src.FieldNumber,
		FieldType:    uint(encField.OriginalType),
		FieldContent: decData,
	}, nil
}

func encryptField(src protoField, gcm cipher.AEAD) (dst protoField, err error) {
	nonce, err := generateNonce(gcm)
	if err != nil {
		return dst, err
	}

	encData := gcm.Seal(nonce, nonce, src.FieldContent, nil)

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
