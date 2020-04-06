package protocrypt

import "github.com/golang/protobuf/proto"

// ProtoCrypt is a interface to a Protobuf Field Encrypter / Decrypter
//
// Encryption usage:
//      // Assuming data is a byte slice with the original protobuf in wire format
//      pc := protocrypt.New(data)
//
//      key, err := protocrypt.GenerateKey()
//      if err != nil {
//          panic(err)
//      }
//
//      err = pc.EncryptFields([]uint{1,3}, key)
//      if err != nil {
//          panic(err)
//      }
//
//      data = pc.Serialize()
//      // data now contains encrypted fields 1 and 3 with the specified key
//
// Decryption usage:
//  pc = protocrypt.New(data)
//
//  y := &sample.TestMessage{}
//
//  err = pc.DecryptAndUnmarshal([]uint{1,3}, key, y)
//  if err != nil {
//      panic(err)
//  }
//
//  // Now y is filled with decrypted data
type ProtoCrypt interface {
	// EncryptFields encrypts the specified fields with the specified key
	// If you call more than once, it will encrypt the already encrypted payload
	EncryptFields(fieldsToEncrypt []uint, key []byte) error
	// DecryptFields decrypts the specified fields with the specified key
	// If you call more than once, it will try to decrypt a decrypted content
	DecryptFields(fieldsToDecrypt []uint, key []byte) error
	// Serialize serializes the protobuf to protobuf wire format (compatible with proto.Marshal / Unmarshal
	Serialize() []byte
	// Unmarshal unmarshals the protocrypt loaded data into a protobuf message
	// Equivalent to call proto.Unmarshal(pc.Serialize(), pb)
	Unmarshal(pb proto.Message) error
	// DecryptAndUnmarshal decrypts and unmarshals protocrypt loaded data into a protobuf message
	// Equivalent to call DecryptFilds then Unmarshal
	DecryptAndUnmarshal(fieldsToEncrypt []uint, key []byte, pb proto.Message) error
}

// New returns a instance of ProtoCrypt for the specified protobuf wire binary data
func New(data []byte) ProtoCrypt {
	return parseProto(data)
}
