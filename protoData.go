package protocrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/golang/protobuf/proto"
	"github.com/racerxdl/protocrypt/internal"
)

type protoData struct {
	Fields map[uint]protoField
}

func (pd *protoData) Unmarshal(pb proto.Message) error {
	return proto.Unmarshal(pd.Serialize(), pb)
}

func (pd *protoData) DecryptAndUnmarshal(fieldsToEncrypt []uint, key []byte, pb proto.Message) error {
	err := pd.DecryptFields(fieldsToEncrypt, key)
	if err != nil {
		return err
	}
	return pd.Unmarshal(pb)
}

func (pd *protoData) EncryptFields(fieldsToEncrypt []uint, key []byte) error {
	fte := internal.UIntSlice(fieldsToEncrypt)
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, _ := cipher.NewGCM(c)

	fte.Sort()
	for _, fieldNum := range fte {
		if src, ok := pd.Fields[fieldNum]; ok {
			dst, err := encryptField(src, gcm)
			if err != nil {
				return err
			}
			pd.Fields[fieldNum] = dst
		}
	}

	return nil
}

func (pd *protoData) DecryptFields(fieldsToDecrypt []uint, key []byte) error {
	ftd := internal.UIntSlice(fieldsToDecrypt)
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, _ := cipher.NewGCM(c)

	for _, fieldNum := range ftd {
		if src, ok := pd.Fields[fieldNum]; ok {
			dst, err := decryptField(src, gcm)
			if err != nil {
				return err
			}
			pd.Fields[fieldNum] = dst
		}
	}

	ftd.Sort()
	return nil
}

func (pd *protoData) Serialize() []byte {
	b := bytes.NewBuffer(nil)

	for _, v := range pd.Fields {
		b.Write(v.Encode())
	}

	return b.Bytes()
}
