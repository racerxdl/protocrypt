package protocrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/golang/protobuf/proto"
	"testing"
)

func TestEncryptDecryptField(t *testing.T) {
	testKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

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

	if bytes.Equal(unc.FieldContent, src.FieldContent) {
		t.Error("Expected field content to not change")
	}

	// Test corruptin

	dst.FieldContent[5] = 0xF0
	dst.FieldContent[6] = 0xF1

	// Decrypt
	unc, err = decryptField(dst, gcm)
	if err == nil {
		t.Error("Expected error on field corruption but got none")
	}
}
