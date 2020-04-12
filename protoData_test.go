package protocrypt

import (
	"bytes"
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"github.com/racerxdl/protocrypt/internal"
	"math"
	"math/rand"
	"testing"
)

func TestProtoData_DecryptAndUnmarshal(t *testing.T) {
	randData, _ := GenerateKey()
	randData2, _ := GenerateKey()

	x := &internal.EncryptedField{
		OriginalType: rand.Uint32(),
		Nonce:        randData,
		Content:      randData2,
	}

	data, _ := proto.Marshal(x)

	pb := New(data)

	err := pb.EncryptFields([]uint{1, 2, 3}, randData)

	if err != nil {
		t.Fatal(err)
	}

	y := &internal.EncryptedField{}

	err = pb.DecryptAndUnmarshal([]uint{1, 2, 3}, randData, y)
	if err != nil {
		t.Fatal(err)
	}

	if x.OriginalType != y.OriginalType {
		t.Errorf("Expected Original Type to be preserved. Expected %d got %d", x.OriginalType, y.OriginalType)
	}

	if !bytes.Equal(x.Nonce, y.Nonce) && !bytes.Equal(x.Content, y.Content) {
		t.Error("Expected Content to be preserved.")
	}
}

func TestProtoData_EncryptFields(t *testing.T) {
	testKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	fields := map[uint]protoField{
		1: {
			FieldNumber:  1,
			FieldType:    proto.WireBytes,
			FieldContent: []byte("abcde"),
		},
		2: {
			FieldNumber:  2,
			FieldType:    proto.WireVarint,
			FieldContent: buildUVarint(12345),
		},
		3: {
			FieldNumber:  3,
			FieldType:    proto.WireFixed64,
			FieldContent: make([]byte, 8),
		},
		4: {
			FieldNumber:  4,
			FieldType:    proto.WireFixed32,
			FieldContent: make([]byte, 4),
		},
	}

	binary.LittleEndian.PutUint64(fields[3].FieldContent, math.Float64bits(15.34))
	binary.LittleEndian.PutUint32(fields[4].FieldContent, math.Float32bits(15.34))

	pb := &protoData{
		Fields: make(map[uint]protoField),
	}

	// Copy original map to ensure no references
	for i, v := range fields {
		pb.Fields[i] = protoField{
			FieldNumber:  v.FieldNumber,
			FieldType:    v.FieldType,
			FieldContent: make([]byte, len(v.FieldContent)),
		}
		copy(pb.Fields[i].FieldContent, v.FieldContent)
	}

	err = pb.EncryptFields([]uint{1, 2, 3, 4}, testKey)
	if err != nil {
		t.Fatalf("Error encrypting data: %s", err)
	}

	for i, v := range pb.Fields {
		if fields[i].FieldNumber != v.FieldNumber {
			t.Errorf("[%d] Field number shouldn't change on encryption. Expected %d got %d", i, fields[i].FieldNumber, v.FieldNumber)
		}

		if v.FieldType != proto.WireBytes {
			t.Errorf("[%d] Expected encrypted field type to be bytes. Got %d", i, v.FieldType)
		}

		if bytes.Equal(v.FieldContent, fields[i].FieldContent) {
			t.Errorf("[%d] Expected content to be encrypt but found plaintext", i)
		}
	}

	err = pb.EncryptFields([]uint{1, 2, 3, 4}, []byte("abcd"))
	if err == nil {
		t.Errorf("Expected error for invalid key length")
	}
}

func TestProtoData_DecryptFields(t *testing.T) {
	testKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	fields := map[uint]protoField{
		1: {
			FieldNumber:  1,
			FieldType:    proto.WireBytes,
			FieldContent: []byte("abcde"),
		},
		2: {
			FieldNumber:  2,
			FieldType:    proto.WireVarint,
			FieldContent: buildUVarint(12345),
		},
		3: {
			FieldNumber:  3,
			FieldType:    proto.WireFixed64,
			FieldContent: make([]byte, 8),
		},
		4: {
			FieldNumber:  4,
			FieldType:    proto.WireFixed32,
			FieldContent: make([]byte, 4),
		},
	}

	binary.LittleEndian.PutUint64(fields[3].FieldContent, math.Float64bits(15.34))
	binary.LittleEndian.PutUint32(fields[4].FieldContent, math.Float32bits(15.34))

	pb := &protoData{
		Fields: fields,
	}

	err = pb.EncryptFields([]uint{1, 2, 3}, testKey)
	if err != nil {
		t.Fatalf("Error encrypting data: %s", err)
	}

	err = pb.DecryptFields([]uint{1, 2, 3}, testKey)
	if err != nil {
		t.Fatalf("Error decrypting data: %s", err)
	}

	for i, v := range pb.Fields {
		if fields[i].FieldNumber != v.FieldNumber {
			t.Errorf("[%d] Field number shouldn't change on encryption. Expected %d got %d", i, fields[i].FieldNumber, v.FieldNumber)
		}

		if fields[i].FieldType != v.FieldType {
			t.Errorf("[%d] Expected encrypted field type to be preserved. Expected %d Got %d", i, fields[i].FieldType, v.FieldType)
		}

		if !bytes.Equal(v.FieldContent, fields[i].FieldContent) {
			t.Errorf("[%d] Expected content to be preserved", i)
		}
	}

	// Test data corruption

	_ = pb.EncryptFields([]uint{1, 2, 3}, testKey)

	pb.Fields[1].FieldContent[2] = 0xF1
	pb.Fields[1].FieldContent[3] = 0xF2
	pb.Fields[1].FieldContent[4] = 0xF3

	err = pb.DecryptFields([]uint{1, 2, 3}, testKey)
	if err == nil {
		t.Fatalf("Expected decryption error but got none")
	}
}

func TestProtoData_Serialize(t *testing.T) {
	randData, _ := GenerateKey()
	randData2, _ := GenerateKey()

	x := &internal.EncryptedField{
		OriginalType: rand.Uint32(),
		Nonce:        randData,
		Content:      randData2,
	}

	data, _ := proto.Marshal(x)

	pb := New(data)
	data = pb.Serialize()

	pb = New(data)

	y := &internal.EncryptedField{}

	err := pb.Unmarshal(y)
	if err != nil {
		t.Fatal(err)
	}

	if x.OriginalType != y.OriginalType {
		t.Errorf("Expected Original Type to be preserved. Expected %d got %d", x.OriginalType, y.OriginalType)
	}

	if !bytes.Equal(x.Nonce, y.Nonce) && !bytes.Equal(x.Content, y.Content) {
		t.Error("Expected Content to be preserved.")
	}
}

func TestProtoData_Unmarshal(t *testing.T) {
	randData, _ := GenerateKey()
	randData2, _ := GenerateKey()

	x := &internal.EncryptedField{
		OriginalType: rand.Uint32(),
		Nonce:        randData,
		Content:      randData2,
	}

	data, _ := proto.Marshal(x)

	pb := New(data)

	y := &internal.EncryptedField{}

	err := pb.Unmarshal(y)
	if err != nil {
		t.Fatal(err)
	}

	if x.OriginalType != y.OriginalType {
		t.Errorf("Expected Original Type to be preserved. Expected %d got %d", x.OriginalType, y.OriginalType)
	}

	if !bytes.Equal(x.Nonce, y.Nonce) && !bytes.Equal(x.Content, y.Content) {
		t.Error("Expected Content to be preserved.")
	}
}
