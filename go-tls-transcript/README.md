```
go test
```

This module will execute handshakes (in-memory) and dump the raw transcript bytes and key logs into the resources folder.

Supposedly X25519MLKEM768 was enabled by default in Go 1.25, but I am not observing that

code: https://cs.opensource.google/go/go/+/master:src/crypto/tls/defaults.go;l=20;drc=3a3c006ac07886aa923a8aad0a4b3ed954640973

See the following issue: https://github.com/golang/go/issues/69985

crypto/tls: add X25519MLKEM768 and use by default; remove x25519Kyber768Draft00