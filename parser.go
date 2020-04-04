package protocrypt

import (
	"encoding/binary"
	"fmt"
	"github.com/golang/protobuf/proto"
)

type protoField struct {
	FieldNumber  uint
	FieldType    uint
	FieldContent []byte
}

func (pf protoField) Encode() []byte {
	key := uint64(pf.FieldType) | uint64(pf.FieldNumber)<<3
	data := buildUVarint(key)

	switch pf.FieldType {
	case proto.WireVarint:
		data = append(data, pf.FieldContent...)
	case proto.WireFixed64: // 64 bit
		data = append(data, pf.FieldContent...)
	case proto.WireBytes:
		data = append(data, buildUVarint(uint64(len(pf.FieldContent)))...)
		data = append(data, pf.FieldContent...)
	case proto.WireFixed32: // 32 bit
		data = append(data, pf.FieldContent...)
	}

	return data
}

func decodeKey(val uint64) (fieldNumber, fieldType uint) {
	fieldType = uint(val & 3)
	fieldNumber = uint(val >> 3)

	return fieldNumber, fieldType
}

func decodeNext(data []byte) ([]byte, protoField, error) {
	pf := protoField{}

	v, n := binary.Uvarint(data)
	data = data[n:]

	fn, ft := decodeKey(v)

	pf.FieldType = ft
	pf.FieldNumber = fn

	switch ft {
	case proto.WireVarint:
		_, n = binary.Uvarint(data)
		pf.FieldContent = data[:n]
		data = data[n:]
	case proto.WireFixed64: // 64 bit
		pf.FieldContent = data[:8]
		data = data[8:]
	case proto.WireBytes:
		v, n = binary.Uvarint(data)
		data = data[n:]
		content := data[:v]
		data = data[v:]

		pf.FieldContent = content
	case proto.WireStartGroup: // Start Group (Deprecated)
		return data, pf, fmt.Errorf("start group is deprecated. not supported by protocrypt")
	case proto.WireEndGroup: // End Group (Deprecated)
		return data, pf, fmt.Errorf("end group is deprecated. not supported by protocrypt")
	case proto.WireFixed32: // 32 bit
		pf.FieldContent = data[:4]
		data = data[4:]
	}

	return data, pf, nil
}

func parseProto(data []byte) *protoData {
	var err error
	var pf protoField

	pd := &protoData{
		Fields: make(map[uint]protoField),
	}
	for err == nil && len(data) > 0 {
		data, pf, err = decodeNext(data)
		if err == nil {
			pd.Fields[pf.FieldNumber] = pf
		}
	}

	return pd
}
