# Go Transcript Generator

The package/module/whatever it's called in go contains logic to 
1. setup a go TLS client and server with library defaults
2. handshake them over shared memory
3. dump the binary transcript and the key log to the `resources/<go version>` folder
4. then the rust `go_transcripts` test in `offline.rs` will dump the decrypted transcript to `brass-aphid-wire/resources/traces/`


The transcripts and key logs can be generated just by running
```
go test
```

## Go Versions
`all_go_transcripts.sh` will use podman with the Go docker images to generate transcripts for all versions of the Go library between 1.16 and 1.25. We can't go below 1.16 because we use `os.ReadFile` and I am too lazy to look up the more broadly compatible method.

`specific_go_transcript.sh` can be used to get the transcript/keys from a specific go version.

### X25519MLKEM768?

Supposedly X25519MLKEM768 was enabled by default in Go 1.25, but I am not observing that

I opened an issue for it here: https://github.com/golang/go/issues/75453

[crypto/tls: add X25519MLKEM768 and use by default; remove x25519Kyber768Draft00](https://github.com/golang/go/issues/69985)

This issue is closed and resolved. I can see the intended defaults here, but I for some reason I don't seem to be using those: https://cs.opensource.google/go/go/+/master:src/crypto/tls/defaults.go;l=20;drc=3a3c006ac07886aa923a8aad0a4b3ed954640973

Note that when I modify `specific_go_transcript.sh` to include `GODEBUG=tlsmlkem=1`, then I do see X25519MLKEM768 in the client's supported groups.

I would prefer to just write this as a test which exposes the negotiated key exchange group and fails/passes, but I am too smooth brained to figure out how to programmatically access that information on the go TLS connection.