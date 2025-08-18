import java.io.*;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * TranscriptDumper handles writing TLS transcripts to binary files
 * in the same format as the Go implementation.
 */
public class TranscriptDumper {
    
    /**
     * Dumps a transcript to a binary file matching the Go format:
     * For each transmission: [peer_byte][8_byte_length][data]
     */
    public static void dumpTranscript(String filename, List<Transmission> transcript) throws IOException {
        String outFile = filename + "_transcript.bin";
        
        try (FileOutputStream fos = new FileOutputStream(outFile);
             BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            
            for (Transmission t : transcript) {
                // Write peer byte ('c' for client, 's' for server)
                byte peerByte = getPeerByte(t.name);
                bos.write(peerByte);
                
                // Write data length as 8-byte big-endian integer
                ByteBuffer lengthBuffer = ByteBuffer.allocate(8);
                lengthBuffer.putLong(t.data.length);
                bos.write(lengthBuffer.array());
                
                // Write the actual data
                bos.write(t.data);
            }
        }
        
        System.out.println("Transcript written to: " + outFile);
    }
    
    private static byte getPeerByte(String peer) {
        switch (peer) {
            case "client":
                return (byte) 'c';
            case "server":
                return (byte) 's';
            default:
                throw new IllegalArgumentException("Unknown peer: " + peer);
        }
    }
}
