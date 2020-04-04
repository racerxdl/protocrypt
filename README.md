[![Coverage Status](https://coveralls.io/repos/github/racerxdl/protocrypt/badge.svg?branch=master)](https://coveralls.io/github/racerxdl/protocrypt?branch=master) ![Push Tests](https://github.com/racerxdl/protocrypt/workflows/Push%20Tests/badge.svg) [![DeepSource](https://static.deepsource.io/deepsource-badge-light-mini.svg)](https://deepsource.io/gh/racerxdl/protocrypt/?ref=repository-badge)

# ProtoCrypt

Protobuf Transparent Encryption

This library encrypts protobuf fields without knowing the underline model. It uses AES-256-GCM to do so.

The usage is pretty simple:

```bash
go get github.com/racerxdl/protocrypt
```

```go
	// Assuming data is a byte slice with the proto content:
	pc := protocrypt.New(data)
	key := []byte("passphrasewhichneedstobe32bytes!")
	err = pc.EncryptFields([]uint{1,3}, key) // Encrypt fields 1 and 3
	if err != nil {
		panic(err)
	}

	data = pc.Serialize()
	// Data now contains the original protobuf with fields 1 and 3 encrypted.
```

```go
	pc := protocrypt.New(data)
	key := []byte("passphrasewhichneedstobe32bytes!")
	err = pc.Decrypt([]uint{1,3}, key)
	if err != nil {
		panic(err)
	}

	data = pc.Serialize() // Data now contains the protobuf with fields 1 and 3 decrypted
```

