package protocrypt

import "github.com/golang/protobuf/proto"

type ProtoCrypt interface {
	EncryptFields(fieldsToEncrypt []uint, key []byte) error
	DecryptFields(fieldsToDecrypt []uint, key []byte) error
	Serialize() []byte
	Unmarshal(pb proto.Message) error
	DecryptAndUnmarshal(fieldsToEncrypt []uint, key []byte, pb proto.Message) error
}

// New returns a instance of ProtoCrypt for the specified binary data
func New(data []byte) ProtoCrypt {
	return parseProto(data)
}
