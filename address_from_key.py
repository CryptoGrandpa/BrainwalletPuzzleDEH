"""
Derive a Bitcoin legacy (P2PKH) address from a numeric private key.

Pipeline:
  private key (int) -> public key (EC point on secp256k1)
                     -> SHA-256 -> RIPEMD-160 (= hash160)
                     -> Base58Check encode (version byte 0x00 + checksum)
"""
import hashlib
import ecdsa
import base58

SECP256K1_ORDER = ecdsa.SECP256k1.order

def private_key_to_wif_bytes(priv_int: int) -> bytes:
    if not (0 < priv_int < SECP256K1_ORDER):
        raise ValueError("Private key out of valid range for secp256k1")
    return priv_int.to_bytes(32, byteorder="big")

def private_key_to_public_key(priv_int: int, compressed: bool = True) -> bytes:
    priv_bytes = private_key_to_wif_bytes(priv_int)
    signing_key = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    point = verifying_key.pubkey.point

    x = point.x().to_bytes(32, byteorder="big")
    y = point.y().to_bytes(32, byteorder="big")

    if compressed:
        prefix = b"\x02" if point.y() % 2 == 0 else b"\x03"
        return prefix + x
    else:
        return b"\x04" + x + y

def hash160(data: bytes) -> bytes:
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_hash)
    return ripemd160.digest()

def public_key_to_address(pubkey_bytes: bytes, version_byte: bytes = b"\x00") -> str:
    h160 = hash160(pubkey_bytes)
    versioned_payload = version_byte + h160
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    return base58.b58encode(versioned_payload + checksum).decode()

def private_key_int_to_address(priv_int: int, compressed: bool = True) -> str:
    pubkey = private_key_to_public_key(priv_int, compressed=compressed)
    return public_key_to_address(pubkey)

if __name__ == "__main__":
    example_key = 12345678901234567890

    address_compressed = private_key_int_to_address(example_key, compressed=True)
    address_uncompressed = private_key_int_to_address(example_key, compressed=False)

    print(f"Private key (int): {example_key}")
    print(f"Address (compressed pubkey):   {address_compressed}")
    print(f"Address (uncompressed pubkey): {address_uncompressed}")
