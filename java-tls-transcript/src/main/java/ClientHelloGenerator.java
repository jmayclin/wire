import javax.net.ssl.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/**
 * ClientHelloGenerator - Generates TLS client hello messages for different Java versions.
 * 
 * This program initializes an SSLEngine to begin a TLS handshake and captures
 * the client hello message without performing actual network I/O.
 */
public class ClientHelloGenerator {
    public static void main(String[] args) {
        try {
            // Get Java version for directory naming
            String javaVersion = System.getProperty("java.version");
            String shortVersion = getShortVersion(javaVersion);
            System.out.println("Java version: " + javaVersion + " (short: " + shortVersion + ")");
            
            // Create output directory
            Path resourceDir = Paths.get("resources", shortVersion);
            Files.createDirectories(resourceDir);
            
            // Generate and save client hello
            ByteBuffer clientHello = generateClientHello();
            Path outputPath = resourceDir.resolve("client_hello.bin");
            saveToFile(clientHello, outputPath);
            
            System.out.println("Client hello saved to: " + outputPath);
        } catch (Exception e) {
            System.err.println("Error generating client hello: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    /**
     * Extracts the short version number from the full Java version string.
     * 
     * @param fullVersion The full Java version string
     * @return The short version (8, 11, 17, etc.)
     */
    private static String getShortVersion(String fullVersion) {
        // Handle different version formats
        if (fullVersion.startsWith("1.")) {
            // Java 8 format: 1.8.0_XXX
            return "8";
        } else {
            // Java 9+ format: 11.0.X, 17.0.X, etc.
            int dotIndex = fullVersion.indexOf('.');
            if (dotIndex > 0) {
                return fullVersion.substring(0, dotIndex);
            } else {
                // Just in case there's no dot
                return fullVersion;
            }
        }
    }
    
    private static ByteBuffer generateClientHello() throws Exception {
        // Create SSLEngine
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine("localhost", 443);
        engine.setUseClientMode(true);
        
        // Allocate buffers for the handshake
        SSLSession session = engine.getSession();
        ByteBuffer appOut = ByteBuffer.allocate(0);
        ByteBuffer netOut = ByteBuffer.allocate(session.getPacketBufferSize());
        
        // Begin handshake to generate client hello
        engine.beginHandshake();
        SSLEngineResult result = engine.wrap(appOut, netOut);
        
        if (result.getStatus() != SSLEngineResult.Status.OK) {
            throw new Exception("SSLEngine wrap failed with status: " + result.getStatus());
        }
        
        // Prepare the output buffer with the complete TLS record (including header)
        netOut.flip();
        
        // Create a copy of the entire buffer including the TLS record header
        ByteBuffer clientHello = ByteBuffer.allocate(netOut.remaining());
        clientHello.put(netOut);
        clientHello.flip();
        
        return clientHello;
    }
    
    private static void saveToFile(ByteBuffer buffer, Path path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path.toFile())) {
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            fos.write(bytes);
        }
    }
}
