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

We also make an effort to set the `go` directive in `go.mod` to match the current chain version because of default `GODEBUG` issues.

## Go Defaults vs GODEBUG
https://github.com/golang/go/issues/75453

Go defaults are influenced by the `go` directive on `go.mod`. I think this is like Go's version of MSRV? Even if the toolchain is more recent, go will try and set the GODEBUG values to maintain maximum similarity with the version specified in the `go` directive.

For example, X25519MLKEM768 is enabled by default in go 1.24+. But if the go directive in `go.mod` is less than 1.24 than `GODEBUG=tlsmlkem=0` is automatically set. 

`specific_go_transcript.sh` can be used to get the transcript/keys from a specific go version.