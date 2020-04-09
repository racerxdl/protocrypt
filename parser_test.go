package protocrypt

import (
	"bytes"
	"github.com/golang/protobuf/proto"
	"math/rand"
	"testing"
)

func TestDecodeNextErrors(t *testing.T) {
	pf := protoField{
		FieldNumber:  uint(rand.Uint32()),
		FieldType:    proto.WireStartGroup,
		FieldContent: make([]byte, 10),
	}

	data := pf.Encode()
	_, _, err := decodeNext(data)
	if err == nil {
		t.Errorf("Expected WireStartGroup to trigger an error, but got none")
	}

	pf.FieldType = proto.WireEndGroup
	data = pf.Encode()
	_, _, err = decodeNext(data)
	if err == nil {
		t.Errorf("Expected WireStartGroup to trigger an error, but got none")
	}
}

func TestProtoField_Encode(t *testing.T) {
	randomBytes, _ := GenerateKey()

	pf := protoField{
		FieldNumber:  uint(rand.Uint32()),
		FieldType:    proto.WireBytes,
		FieldContent: randomBytes,
	}

	data := pf.Encode()

	resultingBytes, newPf, err := decodeNext(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(resultingBytes) > 0 {
		t.Errorf("Expected resulting bytes to be zero. Got %d", len(resultingBytes))
	}

	if newPf.FieldNumber != pf.FieldNumber {
		t.Errorf("Expected fieldNumber to be %d got %d", pf.FieldNumber, newPf.FieldNumber)
	}

	if newPf.FieldType != pf.FieldType {
		t.Errorf("Expected fieldNumber to be %d got %d", pf.FieldNumber, newPf.FieldNumber)
	}

	if bytes.Equal(newPf.FieldContent, pf.FieldContent) {
		t.Errorf("Expected fieldContent to be preserved")
	}
}
