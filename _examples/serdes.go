package main

import (
	"github.com/golang/protobuf/proto"
	"github.com/racerxdl/protocrypt"
	"github.com/racerxdl/protocrypt/_examples/sample"
	"os"
)

func main() {
	x := &sample.TestMessage{
		Value: "huebr",
		SubValue: &sample.SubMessage{
			StringVal: "my amazing val",
			IntVal: 0xFFFF,
			Int64Val: 0x0FFF0000FFFF0000,
			Huebr: []byte("abcd huebr 4"),
		},
		MyData: []byte("My amazing data"),
	}

	data, err := proto.Marshal(x)

	if err != nil {
		panic(err)
	}

	pc := protocrypt.New(data)


	key, err := protocrypt.GenerateKey()
	if err != nil {
		panic(err)
	}

	err = pc.EncryptFields([]uint{1,3}, key)
	if err != nil {
		panic(err)
	}

	data = pc.Serialize()

	f, _ := os.Create("sample.bin")
	_, _ = f.Write(data)
	_ = f.Close()

	pc = protocrypt.New(data)

	y := &sample.TestMessage{}

	err = pc.DecryptAndUnmarshal([]uint{1,3}, key, y)
	if err != nil {
		panic(err)
	}

	data, _ = proto.Marshal(y)

	f, _ = os.Create("sample.bin.dec")
	_, _ = f.Write(data)
	_ = f.Close()
}
