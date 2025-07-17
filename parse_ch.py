import binascii
import struct
from collections import namedtuple

# Paste your hex string (can contain newlines or spaces)
raw_hex = """
01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38
        c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef
        62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01
        00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76
        65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
        17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
        23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
        e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e
        51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00
        03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
        02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
        04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
        00 02 40 01
"""

data = bytes.fromhex(raw_hex)

def read_bytes(data, offset, length):
    return data[offset:offset+length], offset + length

def read_uint(data, offset, size):
    val = int.from_bytes(data[offset:offset+size], 'big')
    return val, offset + size

def parse_tls_record(data):
    offset = 0
    content_type, offset = read_uint(data, offset, 1)
    version, offset = read_uint(data, offset, 2)
    length, offset = read_uint(data, offset, 2)

    print(f"TLS Record Header:")
    print(f"  Content Type: {content_type:#04x} (Handshake)")
    print(f"  Version: {version:#06x} (TLS 1.2 for record layer)")
    print(f"  Length: {length} bytes\n")
    
    return offset

def parse_handshake_header(data, offset):
    handshake_type, offset = read_uint(data, offset, 1)
    length, offset = read_uint(data, offset, 3)

    print(f"Handshake Message:")
    print(f"  Type: {handshake_type:#04x} (ClientHello)")
    print(f"  Length: {length} bytes\n")

    return offset

def parse_client_hello(data, offset):
    version, offset = read_uint(data, offset, 2)
    random, offset = read_bytes(data, offset, 32)

    session_id_len, offset = read_uint(data, offset, 1)
    session_id, offset = read_bytes(data, offset, session_id_len)

    cipher_suites_len, offset = read_uint(data, offset, 2)
    cipher_suites_raw, offset = read_bytes(data, offset, cipher_suites_len)
    cipher_suites = [cipher_suites_raw[i:i+2].hex() for i in range(0, cipher_suites_len, 2)]

    compression_methods_len, offset = read_uint(data, offset, 1)
    compression_methods, offset = read_bytes(data, offset, compression_methods_len)

    extensions_len, offset = read_uint(data, offset, 2)
    extensions_end = offset + extensions_len

    print(f"ClientHello:")
    print(f"  Client Version: {version:#06x}")
    print(f"  Random: {random.hex()}")
    print(f"  Session ID Length: {session_id_len}")
    print(f"  Session ID: {session_id.hex()}")
    print(f"  Cipher Suites ({len(cipher_suites)}): {', '.join(cipher_suites)}")
    print(f"  Compression Methods: {compression_methods.hex()}")
    print(f"  Extensions Length: {extensions_len}")

    while offset < extensions_end:
        ext_type, offset = read_uint(data, offset, 2)
        ext_len, offset = read_uint(data, offset, 2)
        ext_data, offset = read_bytes(data, offset, ext_len)

        print(f"    Extension: {ext_type:#06x}, Length: {ext_len}")
        if ext_type == 0x0000:
            # server_name
            print(f"      Server Name Extension: {ext_data.hex()}")
        elif ext_type == 0x000a:
            # supported_groups
            groups_len = int.from_bytes(ext_data[0:2], 'big')
            groups = [ext_data[i:i+2].hex() for i in range(2, 2 + groups_len, 2)]
            print(f"      Supported Groups: {groups}")
        elif ext_type == 0x000d:
            # signature_algorithms
            sigalgs_len = int.from_bytes(ext_data[0:2], 'big')
            sigalgs = [ext_data[i:i+2].hex() for i in range(2, 2 + sigalgs_len, 2)]
            print(f"      Signature Algorithms: {sigalgs}")
        elif ext_type == 0x002b:
            # supported_versions
            ver_len = ext_data[0]
            versions = [ext_data[i:i+2].hex() for i in range(1, 1 + ver_len, 2)]
            print(f"      Supported Versions: {versions}")
        elif ext_type == 0x0033:
            # key_share
            print(f"      Key Share: {ext_data.hex()}")
        elif ext_type == 0x002d:
            print(f"      PSK Key Exchange Modes: {ext_data.hex()}")
        else:
            print(f"      (Unknown or unparsed extension)")

def main():
    offset = parse_tls_record(data)
    offset = parse_handshake_header(data, offset)
    parse_client_hello(data, offset)

if __name__ == "__main__":
    main()
