# Key Logging Behaviors

s2n-tls, rustls, and openssl all see to be logging their keys at different times, which is making things tricky for me.

First off, my IO setup is

```
                        
 DecryptingPipe::read() 
                        
         │              
         │    T::read() 
         ├──────┐       
         │      │       
         │      │       
         │      │       
         │      │       
         │      ▼       
         │◄──────       
         │              
         │              
         │1. assemble   
         │2. parse/decrypt    
         │              
         │              
         ▼              
                        
```

### s2n-tls behavior
Keys are eagerly derived. E.g. Let's say that the connection just read in the server-finished. 
1. Connection reads ServerFinished
2. T::read
    1. server finished parsed
    2. traffic secrets derived
    3. key log for traffic secrets
    4. T::read finish
3. Decrypter::assemble
4. Decrypter::parse

In this case, we were able to successful retrieve the traffic space as soon as we say that Finished message, because the keys were available.

### OpenSSL behavior
1. Connection reads ServerFinished
2. T::read
    1. server finished parsed
    2. T::read finish
3. Decrypter::assemble
4. Decrypter::parse

For OpenSSL, the Traffic Keys are _not_ available when the ServerFinished is received, but they will be available before the Decrypter::assemble function actually sees any traffic data, because OpenSSL will derive the secrets as part of T::read when it gets traffic data.

### Rustls behavior
I think the rustls behavior is different because it has a much cleaner IO/state model than s2n-tls or OpenSSL.

Let's examine the case where a server receives encrypted extensions
1. Connection reads EncryptedExtensions
2. T::read
    1. data is stored into internal buffer
3. Decrypter::assemble
4. Decrypter::parse

At this point the Decrypter is unable to proceed. It needs the handshake secrets, but they _haven't been derived yet_. If I recall correctly this is likely because Rustls decouples it's processing from it's lower reading.

```rust
RustlsStream::read(&mut self) {
    // decrypting pipe sees the encrypted data here
    self.decrypting_pipe.read();

    // but the keys aren't encrypted until here.
    self.conn.process_tls();
}
```
