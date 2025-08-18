package susgobench

import (
	"testing"
)

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
