package susgobench

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// Certificate paths
const (
	certFile = "../certs/ecdsa384/server-chain.pem"
	keyFile  = "../certs/ecdsa384/server-key.pem"
	caFile   = "../certs/ecdsa384/ca-cert.pem"
)

func tlsServerConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func resumptionServerConfig() *tls.Config {
	// Generate session ticket keys
	sessionTicketKeys := make([][32]byte, 1)
	if _, err := rand.Read(sessionTicketKeys[0][:]); err != nil {
		log.Fatalf("failed to generate session ticket key: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load key pair: %v", err)
	}

	config := tls.Config{
		Certificates:           []tls.Certificate{cert},
		SessionTicketKey:       sessionTicketKeys[0],
		SessionTicketsDisabled: false,
	}
	return &config
}

func tlsClientConfig() *tls.Config {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to add CA certificate to pool")
	}

	return &tls.Config{
		RootCAs:    caCertPool,
		ServerName: "localhost",
	}
}

func resumptionClientConfig() *tls.Config {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to add CA certificate to pool")
	}

	return &tls.Config{
		RootCAs:                caCertPool,
		ClientSessionCache:     NewLoggingSessionCache(128),
		ServerName:             "localhost",
		SessionTicketsDisabled: false,
	}
}

func getGoVersion() string {
	return runtime.Version()
}

func harness_handshake(caseName string, clientConfig, serverConfig *tls.Config) {
	goVersion := getGoVersion()
	resourceDir := filepath.Join("resources", goVersion)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(resourceDir, 0755); err != nil {
		log.Fatalf("failed to create directory: %v", err)
	}

	outFile := filepath.Join(resourceDir, caseName+"_keys.log")
	f, err := os.Create(outFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	clientConfig.KeyLogWriter = f

	clientTransport, serverTransport, transcript := NewClientServerRecordingPipe()

	clientConn := tls.Client(clientTransport, clientConfig)
	serverConn := tls.Server(serverTransport, serverConfig)

	log.Println(transcript)

	go func() {
		// I hate this, but I guess necessary bc Go doesn't allow shadowing?
		if err := serverConn.Handshake(); err != nil {
			log.Println("server handshake failed")
			log.Println((err))
		}
		log.Println("server handshake finished")

		log.Println("server is closing")

		readBuf := make([]byte, 1)
		_, err := serverConn.Read(readBuf)
		if err != io.EOF {
			panic(err)
		}

		serverConn.CloseWrite()

		log.Println("server is finished")
	}()

	if err := clientConn.Handshake(); err != nil {
		log.Fatalf("client handshake failed: %v", err)
	}
	state := clientConn.ConnectionState()
	if !state.HandshakeComplete {
		log.Fatal("handshake was not complete")
	}
	readBuf := make([]byte, 1)
	// order important, because we don't want the above readBuf to read in the
	// closeNotify, but we do want it to read in any session tickets.
	clientConn.CloseWrite()
	_, err = clientConn.Read(readBuf)

	// so uggo
	if err != io.EOF {
		panic("client failed to close")
	}

	log.Println("client is finished")

	log.Println("transcript:", transcript)
	DumpTranscript(caseName, transcript)
}

// TODO: This was only used for debugging, when I forget that I have to call read to retrieve the NST bc TLS 1.3 shenanigans
// remove this and just use the underlying NewLRUClientSessionCache
type loggingSessionCache struct {
	cache tls.ClientSessionCache
}

func NewLoggingSessionCache(size int) tls.ClientSessionCache {
	return &loggingSessionCache{
		cache: tls.NewLRUClientSessionCache(size),
	}
}

func (l *loggingSessionCache) Put(key string, cs *tls.ClientSessionState) {
	fmt.Printf("Adding session with key: %s\n", key)
	l.cache.Put(key, cs)
}

func (l *loggingSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	session, ok := l.cache.Get(key)
	if ok {
		fmt.Printf("Retrieved session with key: %s\n", key)
	} else {
		fmt.Printf("No session found with key: %s\n", key)
	}
	return session, ok
}
