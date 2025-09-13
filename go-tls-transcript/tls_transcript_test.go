package susgobench

import (
	"testing"
)

func TestServerAuth(t *testing.T) {
	serverConfig := tlsServerConfig()
	clientConfig := tlsClientConfig()
	harness_handshake("server_auth", clientConfig, serverConfig)
}

// TODO: bad test. make this return the connection state, and then assert on resumption
func TestResumption(t *testing.T) {
	serverConfig := resumptionServerConfig()
	clientConfig := resumptionClientConfig()
	harness_handshake("resumption", clientConfig, serverConfig)
}
