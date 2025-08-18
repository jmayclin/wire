package susgobench

import (
	"testing"
)

// func BenchmarkServerAuthRsa2048(b *testing.B) {
// 	serverConfig := tlsServerConfig(Rsa2048)
// 	clientConfig := tlsClientConfig(Rsa2048)

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		harness_handshake(clientConfig, serverConfig)
// 	}
// }

// func BenchmarkServerAuthEcdsa256(b *testing.B) {
// 	serverConfig := tlsServerConfig(Ecdsa256)
// 	clientConfig := tlsClientConfig(Ecdsa256)

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		harness_handshake(clientConfig, serverConfig)
// 	}
// }

// func BenchmarkServerAuthEcdsa384(b *testing.B) {
// 	serverConfig := tlsServerConfig(Ecdsa384)
// 	clientConfig := tlsClientConfig(Ecdsa384)

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		harness_handshake(clientConfig, serverConfig)
// 	}
// }

// func BenchmarkResumption(b *testing.B) {
// 	// resumption is independent of server auth (as long as it's configured correctly)
// 	// and therefore shouldn't have any dependency on the cert type. Confirmed this
// 	// with a manual run
// 	// RSA2048 ->  361 us
// 	// ECDSA384 -> 362 us
// 	serverConfig := resumptionServerConfig(Rsa2048)
// 	clientConfig := resumptionClientConfig(Rsa2048)

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		harness_handshake(clientConfig, serverConfig)
// 	}
// }

func TestServerAuth(t *testing.T) {
	for _, flavor := range CertFlavors {
		serverConfig := tlsServerConfig(flavor)
		clientConfig := tlsClientConfig(flavor)

		harness_handshake("server_auth", clientConfig, serverConfig)
	}

}

// TODO: bad test. make this return the connection state, and then assert on resumption
func TestResumption(t *testing.T) {
	serverConfig := resumptionServerConfig(Rsa2048)
	clientConfig := resumptionClientConfig(Rsa2048)

	harness_handshake("resumption", clientConfig, serverConfig)
}
