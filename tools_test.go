package protocrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/golang/protobuf/proto"
	"testing"
)

var testKey = []byte("DEADBEEFDEADBEEFDEADBEEF")

func TestEncryptDecryptField(t *testing.T) {
	c, err := aes.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		t.Fatal(err)
	}

	src := protoField{
		FieldNumber:  1,
		FieldType:    proto.WireBytes,
		FieldContent: []byte("huebr"),
	}

	dst, err := encryptField(src, gcm)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt
	unc, err := decryptField(dst, gcm)
	if err != nil {
		t.Fatal(err)
	}

	if unc.FieldType != src.FieldType {
		t.Errorf("Expected field type to not change")
	}

	if unc.FieldNumber != src.FieldNumber {
		t.Error("Expected field number to not change")
	}

	if bytes.Compare(unc.FieldContent, src.FieldContent) != 0 {
		t.Error("Expected field content to not change")
	}
}
