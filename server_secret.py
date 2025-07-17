from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import struct

def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label.encode("ascii")
    hkdf_label = (
        struct.pack("!H", length) +
        bytes([len(full_label)]) + full_label +
        bytes([len(context)]) + context
    )

    print(f"\n=== Deriving {label} ===")
    print(f"Label:       {label}")
    print(f"Full label:  {full_label}")
    print(f"Context:     {context.hex()}")
    print(f"HkdfLabel:   {hkdf_label.hex()}")
    print(f"Output len:  {length}")

    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=hkdf_label,
    )
    return hkdf.derive(secret)

def derive_key_iv(traffic_secret: bytes):
    print("==== Deriving Key and IV ====")
    key = hkdf_expand_label(traffic_secret, "key", b"", 16)
    print(f"Derived Key: {key.hex()}")

    iv = hkdf_expand_label(traffic_secret, "iv", b"", 12)
    print(f"Derived IV:  {iv.hex()}")

    return key, iv

def compute_nonce(iv: bytes, sequence_number: int) -> bytes:
    seq_bytes = sequence_number.to_bytes(12, "big")
    nonce = bytes(iv_byte ^ seq_byte for iv_byte, seq_byte in zip(iv, seq_bytes))
    print(f"\n==== Nonce Computation ====")
    print(f"Sequence #:  {sequence_number}")
    print(f"IV:          {iv.hex()}")
    print(f"SeqBytes:    {seq_bytes.hex()}")
    print(f"Nonce:       {nonce.hex()}")
    return nonce

def parse_tls_record(hex_record: str):
    record = bytes.fromhex(hex_record)
    if len(record) < 5:
        raise ValueError("Record too short")

    content_type = record[0]
    version = record[1:3]
    length = int.from_bytes(record[3:5], "big")
    encrypted = record[5:]

    if len(encrypted) != length:
        raise ValueError("Length mismatch")

    print("\n==== TLS Record ====")
    print(f"ContentType: 0x{content_type:02x}")
    print(f"Version:     0x{version.hex()}")
    print(f"Length:      {length}")
    print(f"Ciphertext:  {encrypted.hex()}")

    return record[:5], encrypted

def decrypt_record(aes_key: bytes, iv: bytes, seq: int, record_header: bytes, encrypted: bytes):
    nonce = compute_nonce(iv, seq)
    aad = record_header
    print(f"\n==== AEAD Decryption ====")
    print(f"AAD:         {aad.hex()}")
    print(f"Nonce:       {nonce.hex()}")
    print(f"Ciphertext:  {encrypted.hex()}")

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, encrypted, aad)
    print(f"\nDecrypted Plaintext: {plaintext.hex()} ({plaintext})")

def main():
    # Example traffic secret
    secret_hex = "1e1e62a87cde245acc002cf9f80574bd15fa3d22c46c9eb59b31db697e83e1b4"
    traffic_secret = bytes.fromhex(secret_hex)

    # TLS record (23 bytes of encrypted data + tag)
    record_hex = "17030300179f39f2f4a6c900f325fc92f5c6a1493a905efbce04771d"

    # Step 1: Derive key/IV
    key, iv = derive_key_iv(traffic_secret)

    # Step 2: Parse record
    record_header, ciphertext = parse_tls_record(record_hex)

    # Step 3: Decrypt record (assume seq=0)
    decrypt_record(key, iv, seq=0, record_header=record_header, encrypted=ciphertext)

if __name__ == "__main__":
    main()