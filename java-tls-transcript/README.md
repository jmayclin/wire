# Java TLS Transcript Generator

This directory contains a Java implementation for generating TLS handshake transcripts, similar to the Go implementation in `../go-tls-transcript/`.

## Overview

The Java TLS transcript generator creates TLS handshake traces using Java's built-in SSL implementation. It captures all TLS traffic in a binary format and logs TLS keys for later analysis.

## Components

- **`JavaTlsTranscript.java`** - Main implementation that uses existing certificates from `../brass-aphid-wire/certs/ecdsa384/`
- **`RecordingPipe.java`** - In-memory communication pipes for client-server data exchange
- **`Transmission.java`** - Data structure representing a TLS transmission
- **`TranscriptDumper.java`** - Utility to write transcripts in binary format

## Usage

```bash
# Compile and run
javac JavaTlsTranscript.java
java JavaTlsTranscript
```

## Output Files

- **`java_tls_transcript.bin`** - Binary transcript file in the same format as Go implementation
- **`java_tls_keys.log`** - TLS key logging output from Java's SSL debug system

## Binary Format

The transcript uses the same binary format as the Go implementation:

```
For each transmission:
[1 byte: peer ('c' for client, 's' for server)]
[8 bytes: data length (big-endian)]
[N bytes: TLS data]
```

## Certificate Usage

This implementation uses the existing ECDSA P-384 certificates from:
- Server certificate chain: `../brass-aphid-wire/certs/ecdsa384/server-chain.pem`
- Server private key: `../brass-aphid-wire/certs/ecdsa384/server-key.pem`
- CA certificate: `../brass-aphid-wire/certs/ecdsa384/ca-cert.pem`

## Features

- **In-memory communication**: All TLS traffic occurs in-memory using custom recording pipes
- **Standard library only**: Uses only Java's built-in SSL/TLS implementation
- **Complete handshake capture**: Records all TLS messages including post-handshake data
- **Key logging**: Captures TLS keys via Java's debug system
- **Compatible format**: Binary output matches the Go implementation format

## Example Output

```
TLS transcript generation completed successfully!
Generated files:
  - java_tls_transcript.bin
  - java_tls_keys.log
```

The transcript typically contains 15+ transmissions representing a complete TLS 1.3 handshake with session tickets and application data.
