package protocrypt

import (
	"bytes"
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"math"
	"testing"
)

func TestNew(t *testing.T) {
	pb := &protoData{
		Fields: map[uint]protoField{
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
		},
	}

	binary.LittleEndian.PutUint64(pb.Fields[3].FieldContent, math.Float64bits(15.34))
	binary.LittleEndian.PutUint32(pb.Fields[4].FieldContent, math.Float32bits(15.34))

	data := pb.Serialize()

	newPb := New(data).(*protoData)

	for i, v := range pb.Fields {
		if newPb.Fields[i].FieldNumber != v.FieldNumber {
			t.Errorf("[%d] Field number shouldn't change on encryption. Expected %d got %d", i, newPb.Fields[i].FieldNumber, v.FieldNumber)
		}

		if newPb.Fields[i].FieldType != v.FieldType {
			t.Errorf("[%d] Expected encrypted field type to be preserved. Expected %d Got %d", i, newPb.Fields[i].FieldType, v.FieldType)
		}

		if bytes.Compare(v.FieldContent, newPb.Fields[i].FieldContent) != 0 {
			t.Errorf("[%d] Expected content to be preserved", i)
		}
	}
}
