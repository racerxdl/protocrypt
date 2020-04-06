package internal

import "testing"

// This file is just to avoid protobuf generated file to lower the coverage

func TestPB(t *testing.T) {
	ef := EncryptedField{}
	ef.ProtoMessage()
	ef.Reset()
	_, _ = ef.Descriptor()
	ef.XXX_Merge(&ef)
	ef.XXX_DiscardUnknown()
	_ = ef.String()

	var nilef *EncryptedField

	_ = nilef.GetOriginalType()
	_ = nilef.GetContent()
	_ = nilef.GetNonce()
}
