import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.net.*;

/**
 * JavaTlsTranscript generates TLS handshake transcripts using the existing certificates.
 */
public class JavaTlsTranscript {
    
    private static final String CERT_PATH = "../brass-aphid-wire/certs/ecdsa384/server-chain.pem";
    private static final String KEY_PATH = "../brass-aphid-wire/certs/ecdsa384/server-key.pem";
    private static final String CA_PATH = "../brass-aphid-wire/certs/ecdsa384/ca-cert.pem";
    
    public static void main(String[] args) {
        try {
            // Enable TLS key logging
            System.setProperty("javax.net.debug", "ssl:handshake:verbose");
            
            // Redirect SSL debug output to our key log file
            PrintStream originalErr = System.err;
            PrintStream keyLogStream = new PrintStream(new FileOutputStream("java_tls_keys.log"));
            System.setErr(keyLogStream);
            
            // Create recording pipes
            RecordingPipe[] pipes = RecordingPipe.createClientServerPair();
            RecordingPipe clientPipe = pipes[0];
            RecordingPipe serverPipe = pipes[1];
            
            // Perform handshake
            performHandshake(clientPipe, serverPipe);
            
            // Restore stderr and close key log
            System.setErr(originalErr);
            keyLogStream.close();
            
            // Dump transcript
            List<Transmission> transcript = clientPipe.getTranscript();
            TranscriptDumper.dumpTranscript("java_tls", transcript);
            
            System.out.println("TLS transcript generation completed successfully!");
            System.out.println("Generated files:");
            System.out.println("  - java_tls_transcript.bin");
            System.out.println("  - java_tls_keys.log");
            
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static void performHandshake(RecordingPipe clientPipe, RecordingPipe serverPipe) throws Exception {
        
        CountDownLatch handshakeComplete = new CountDownLatch(2);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        // Create SSL contexts
        SSLContext clientContext = createClientSSLContext();
        SSLContext serverContext = createServerSSLContext();
        
        // Server thread
        executor.submit(() -> {
            try {
                SSLSocket serverSocket = createSSLSocketWithPipe(serverContext, false, 
                    serverPipe.getInputStream(), serverPipe.getOutputStream());
                
                serverSocket.startHandshake();
                System.out.println("Server handshake completed");
                
                // Read any post-handshake data
                byte[] buffer = new byte[1024];
                try {
                    int bytesRead = serverSocket.getInputStream().read(buffer);
                    if (bytesRead > 0) {
                        System.out.println("Server read " + bytesRead + " bytes");
                    }
                } catch (IOException e) {
                    // Expected when client closes
                }
                
                serverSocket.close();
                handshakeComplete.countDown();
                
            } catch (Exception e) {
                System.err.println("Server error: " + e.getMessage());
                e.printStackTrace();
                handshakeComplete.countDown();
            }
        });
        
        // Client thread
        executor.submit(() -> {
            try {
                SSLSocket clientSocket = createSSLSocketWithPipe(clientContext, true,
                    clientPipe.getInputStream(), clientPipe.getOutputStream());
                
                clientSocket.startHandshake();
                System.out.println("Client handshake completed");
                
                // Send a message to trigger any session tickets
                clientSocket.getOutputStream().write("Hello".getBytes());
                clientSocket.getOutputStream().flush();
                
                clientSocket.close();
                handshakeComplete.countDown();
                
            } catch (Exception e) {
                System.err.println("Client error: " + e.getMessage());
                e.printStackTrace();
                handshakeComplete.countDown();
            }
        });
        
        handshakeComplete.await();
        executor.shutdown();
    }
    
    private static SSLSocket createSSLSocketWithPipe(SSLContext context, boolean clientMode,
                                                   InputStream inputStream, OutputStream outputStream) throws Exception {
        
        Socket dummySocket = new Socket() {
            @Override
            public InputStream getInputStream() throws IOException {
                return inputStream;
            }
            
            @Override
            public OutputStream getOutputStream() throws IOException {
                return outputStream;
            }
            
            @Override
            public void close() throws IOException {
                // No-op
            }
            
            @Override
            public boolean isConnected() {
                return true;
            }
            
            @Override
            public boolean isClosed() {
                return false;
            }
            
            @Override
            public InetAddress getInetAddress() {
                try {
                    return InetAddress.getByName("localhost");
                } catch (Exception e) {
                    return null;
                }
            }
            
            @Override
            public int getPort() {
                return 443;
            }
        };
        
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) factory.createSocket(dummySocket, "localhost", 443, true);
        sslSocket.setUseClientMode(clientMode);
        
        return sslSocket;
    }
    
    private static SSLContext createServerSSLContext() throws Exception {
        // Load the server certificate chain
        X509Certificate[] certChain = loadCertificateChain(CERT_PATH);
        
        // Load the server private key
        PrivateKey privateKey = loadPrivateKey(KEY_PATH);
        
        // Create keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", privateKey, "password".toCharArray(), certChain);
        
        // Create key manager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "password".toCharArray());
        
        // Create SSL context
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, new SecureRandom());
        
        return context;
    }
    
    private static SSLContext createClientSSLContext() throws Exception {
        // Load CA certificate for client trust store
        X509Certificate caCert = loadCertificate(CA_PATH);
        
        // Create trust store
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", caCert);
        
        // Create trust manager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        // Create SSL context
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), new SecureRandom());
        
        return context;
    }
    
    private static X509Certificate[] loadCertificateChain(String path) throws Exception {
        String certContent = readFile(path);
        
        // Split the certificate chain
        String[] certParts = certContent.split("-----END CERTIFICATE-----");
        X509Certificate[] certs = new X509Certificate[certParts.length - 1]; // Last part is empty
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        for (int i = 0; i < certs.length; i++) {
            String certPem = certParts[i] + "-----END CERTIFICATE-----";
            if (certPem.contains("-----BEGIN CERTIFICATE-----")) {
                ByteArrayInputStream bis = new ByteArrayInputStream(certPem.getBytes());
                certs[i] = (X509Certificate) cf.generateCertificate(bis);
            }
        }
        
        return certs;
    }
    
    private static X509Certificate loadCertificate(String path) throws Exception {
        String certContent = readFile(path);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bis = new ByteArrayInputStream(certContent.getBytes());
        return (X509Certificate) cf.generateCertificate(bis);
    }
    
    private static PrivateKey loadPrivateKey(String path) throws Exception {
        String keyContent = readFile(path);
        
        // Remove PEM headers and decode
        keyContent = keyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                              .replace("-----END PRIVATE KEY-----", "")
                              .replaceAll("\\s", "");
        
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        
        // Try EC first (since we're using ECDSA384)
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            // Fallback to RSA if EC fails
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        }
    }
    
    private static String readFile(String path) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
}
