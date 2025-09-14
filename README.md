# omg💅heyyy✨bestie💖lets👪do💌tls🔒

`brass-aphid-wire` is a crate to simplify the parsing of TLS records. It also offers a "runtime decrypter" which allows users to examine a decrypted TLS conversation as it is happening. 

The following are traces from 
- [s2n-tls trace](brass-aphid-wire/resources/traces/s2n-tls.log)
- [openssl trace](brass-aphid-wire/resources/traces/openssl.log)
- [rustls trace (this is currently broken)](brass-aphid-wire/resources/traces/broken-rustls.log)

> [!CAUTION]
> This is very much "in-progress", and is not at all suitable for production. Only TLS 1.3 is supported with the 3 main AEAD ciphers. Generally the library will simply explode/panic if you go off this narrow, happy path. I do intend to eventually make this a production-suitable library, but for now it's best restricted to fiddling about.

# Getting Started.

The two main bits of the public API are the `KeyManager` and the `DecryptingPipe`.

`KeyManager` provides the key logging callback which can be associated with a config like OpenSSL's [`SslContextBuilder::set_keylog_callback`](https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextBuilder.html#method.set_keylog_callback) or s2n-tls's [`Config::set_key_log_callback`](https://docs.rs/s2n-tls/latest/s2n_tls/config/struct.Builder.html#method.set_key_log_callback).

`DecryptingPipe` will wrap some type `T` which implements `Read` and `Write`. This is designed to work with interfaces like OpenSSL's [`SslStream`](https://docs.rs/openssl/latest/openssl/ssl/struct.SslStream.html). If you were previously using `SslStream<TcpStream>`, then you'd swap out the inner `TcpStream` to use the `DecryptingPipe`, yielding an `SslStream<DecryptingPipe<TcpStream>>`.

There aren't any super great examples of this right now, but the best places to look would be
- `brass-aphid-wire/src/bin/decrypting_client.rs`: This file contains a basic TLS client which will print out the full transcript of its handshake against an arbitrary TLS endpoint.
- `brass-aphid-wire/src/testing/openssl_decrypted_transcript.rs`: Sets up a test decrypting with an OpenSSL client and an OpenSSL server.
- `brass-aphid-wire/src/testing/s2n_decrypted_transcript.rs`: Sets up a test decrypting with an s2n-tls client and an s2n-tls server.

# Background

I love snooping. It's one of my favorite activities, but it's hard to do with TLS.

Basically the only option (that I'm aware of) is to use wireshark. This requires you to
1. set up a key logging callback on your TLS server/client
2. figure out how to setup the packet capture stuff to get a `.pcap` file
3. download the pcap file from a remote host to a local host
4. load it into wireshark
5. remind yourself how to load the TLS keys into wireshark
6. remind yourself how to read the wireshark output

And if you want to tweak something and look at the decrypted trace again you get to do it all over.

I am too lazy for that, but too curious to let it go.

- how big are people's session tickets?
- how many do they send?
- how long are they valid for?
- what extensions are in the client hello?
- what signature schemes are offered?
- how large are the records?
- are records coalesced in the handshake phase?

> [!NOTE]
> Yes, I am aware that most of this could be fixed by me just being better at wireshark. 


 Some use cases I think it could unlock in the future.

1. easier debugging of s2n-tls unit tests: My brain is smooth, and the weird C error traces that s2n-tls gives back hurts my brain. I think being able to see exactly what's been read and written would make debugging these things easier.
2. easier debugging of s2n-tls in development: Anecdotally, customer's struggle to configure wireshark as well. When doing development work, `brass-aphid-wire` could help them debug their issues. Ideally this would be something that could be configured based on a simple `feature` in the rust crate.
3. easier debugging/assertions for integration/interop tests: s2n-tls is shifting it's unit tests to rust. Visibility would be nice.


Currently the feature set is relatively limited, and the code is loaded with ~~panics~~ fun surprises where I haven't implemented things.

# Roadmap
- [X] messages across multiple records
- [X] KeyUpdate support
- [X] HelloRetry support
- [X] Offline Decryption (this should just work, tests needed)
- [ ] TLS 1.2 support
- [ ] expand cipher support to CBC (unlikely to support anything else)
- [ ] gate TLS library dependencies behind features
- [ ] switch to RustCrypto instead of AWS-LC for skinniness (and WASM support)
- [ ] separate `brass-aphid-wire` into two crates, one for message codecs, and one for the decryption logic
- [ ] move all of the trace functionality into it's own crate.
