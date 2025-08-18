import java.util.Arrays;

/**
 * Transmission represents a chunk of bytes sent by a TLS participant.
 */
public class Transmission {
    public final String name;
    public final byte[] data;
    
    public Transmission(String name, byte[] data) {
        this.name = name;
        this.data = Arrays.copyOf(data, data.length);
    }
}
