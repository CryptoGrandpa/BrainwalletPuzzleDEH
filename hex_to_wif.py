import sys
import hashlib
import base58
import ecdsa

def hex_to_wif(private_key_hex, compressed=True, testnet=False):
    prefix = b'\xef' if testnet else b'\x80'
    private_key_bytes = bytes.fromhex(private_key_hex)

    extended_key = prefix + private_key_bytes
    if compressed:
        extended_key += b'\x01'

    first_sha = hashlib.sha256(extended_key).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha[:4]

    final_key = extended_key + checksum
    return base58.b58encode(final_key).decode()

def private_key_to_address(private_key_hex, compressed=True, testnet=False):
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Derive public key using secp256k1
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    x = verifying_key.pubkey.point.x()
    y = verifying_key.pubkey.point.y()

    if compressed:
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        public_key_bytes = prefix + x.to_bytes(32, 'big')
    else:
        public_key_bytes = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    # SHA256 then RIPEMD160
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hash160 = ripemd160.digest()

    # Version byte: 0x00 for mainnet, 0x6f for testnet
    version = b'\x6f' if testnet else b'\x00'
    versioned_payload = version + hash160

    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    address_bytes = versioned_payload + checksum

    return base58.b58encode(address_bytes).decode()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 hex_to_wif.py <hex_string>")
        sys.exit(1)

    hex_key = sys.argv[1]
    padded_key = hex_key.zfill(64)
    print(f"Padded key: {padded_key}")
    print()

    wif_compressed = hex_to_wif(padded_key, compressed=True)
    address_compressed = private_key_to_address(padded_key, compressed=True)
    print(f"Compressed:")
    print(f"  WIF:     {wif_compressed}")
    print(f"  Address: {address_compressed}")
    print()

    wif_uncompressed = hex_to_wif(padded_key, compressed=False)
    address_uncompressed = private_key_to_address(padded_key, compressed=False)
    print(f"Uncompressed:")
    print(f"  WIF:     {wif_uncompressed}")
    print(f"  Address: {address_uncompressed}")
