import java.io.*;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * RecordingPipe provides in-memory communication between SSL client and server
 * while recording all transmissions for transcript generation.
 */
public class RecordingPipe {
    private final String name;
    private final BlockingQueue<byte[]> readQueue;
    private final BlockingQueue<byte[]> writeQueue;
    private final List<Transmission> transcript;
    private byte[] readBuffer = new byte[0];
    private int readBufferPos = 0;
    
    private RecordingPipe(String name, BlockingQueue<byte[]> readQueue, 
                         BlockingQueue<byte[]> writeQueue, List<Transmission> transcript) {
        this.name = name;
        this.readQueue = readQueue;
        this.writeQueue = writeQueue;
        this.transcript = transcript;
    }
    
    /**
     * Creates a pair of connected RecordingPipes for client-server communication.
     */
    public static RecordingPipe[] createClientServerPair() {
        BlockingQueue<byte[]> clientToServer = new LinkedBlockingQueue<>();
        BlockingQueue<byte[]> serverToClient = new LinkedBlockingQueue<>();
        List<Transmission> transcript = Collections.synchronizedList(new ArrayList<>());
        
        RecordingPipe client = new RecordingPipe("client", serverToClient, clientToServer, transcript);
        RecordingPipe server = new RecordingPipe("server", clientToServer, serverToClient, transcript);
        
        return new RecordingPipe[]{client, server};
    }
    
    public List<Transmission> getTranscript() {
        return transcript;
    }
    
    /**
     * Creates an InputStream that reads from this pipe.
     */
    public InputStream getInputStream() {
        return new PipeInputStream();
    }
    
    /**
     * Creates an OutputStream that writes to this pipe.
     */
    public OutputStream getOutputStream() {
        return new PipeOutputStream();
    }
    
    private class PipeInputStream extends InputStream {
        @Override
        public int read() throws IOException {
            byte[] buffer = new byte[1];
            int result = read(buffer, 0, 1);
            return result == -1 ? -1 : (buffer[0] & 0xFF);
        }
        
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException();
            }
            if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException();
            }
            if (len == 0) {
                return 0;
            }
            
            // If we don't have data in our buffer, get more from the queue
            if (readBufferPos >= readBuffer.length) {
                try {
                    readBuffer = readQueue.take();
                    readBufferPos = 0;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while reading", e);
                }
            }
            
            // Copy data from our buffer to the destination
            int available = readBuffer.length - readBufferPos;
            int toCopy = Math.min(len, available);
            System.arraycopy(readBuffer, readBufferPos, b, off, toCopy);
            readBufferPos += toCopy;
            
            return toCopy;
        }
        
        @Override
        public void close() throws IOException {
            // No-op for in-memory pipe
        }
    }
    
    private class PipeOutputStream extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }
        
        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException();
            }
            if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException();
            }
            if (len == 0) {
                return;
            }
            
            // Copy the data to send
            byte[] data = new byte[len];
            System.arraycopy(b, off, data, 0, len);
            
            // Send to peer
            writeQueue.offer(data);
            
            // Record in transcript
            transcript.add(new Transmission(name, data));
        }
        
        @Override
        public void flush() throws IOException {
            // No-op for in-memory pipe
        }
        
        @Override
        public void close() throws IOException {
            // No-op for in-memory pipe
        }
    }
}
