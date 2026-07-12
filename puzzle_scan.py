"""
Scan a private key range looking for a target Bitcoin address.
Uses pure-Python ecdsa (no C extension needed) since coincurve
has no prebuilt wheel for this Python version yet.
"""
import hashlib
import time
import ecdsa
import base58

TARGET_ADDRESS = "14oFNXucftsHiUMY8uctg6N487riuyXs4h"
RANGE_START = 0x100000
RANGE_END = 0x1fffff  # inclusive

def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def pubkey_to_address(pubkey_bytes: bytes) -> str:
    payload = b"\x00" + hash160(pubkey_bytes)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def compressed_pubkey_from_point(point) -> bytes:
    x = point.x().to_bytes(32, "big")
    prefix = b"\x02" if point.y() % 2 == 0 else b"\x03"
    return prefix + x

def scan_range(start: int, end: int, target: str):
    curve = ecdsa.SECP256k1
    generator = curve.generator

    # Start at the first key's point via one real multiplication,
    # then use point addition for every subsequent key.
    point = start * generator

    count = 0
    t0 = time.time()
    priv_int = start

    while priv_int <= end:
        pubkey_compressed = compressed_pubkey_from_point(point)
        address = pubkey_to_address(pubkey_compressed)

        count += 1
        if address == target:
            elapsed = time.time() - t0
            print(f"\nMATCH FOUND after {count} keys ({elapsed:.2f}s)")
            print(f"Private key (hex): {hex(priv_int)}")
            print(f"Private key (int): {priv_int}")
            print(f"Address: {address}")
            return priv_int

        if count % 20000 == 0:
            elapsed = time.time() - t0
            rate = count / elapsed
            print(f"Checked {count} keys... ({rate:.0f} keys/sec)")

        point = point + generator  # incremental addition, not full multiply
        priv_int += 1

    print("No match found in range.")
    return None

if __name__ == "__main__":
    print(f"Scanning {RANGE_END - RANGE_START + 1} keys for {TARGET_ADDRESS}")
    scan_range(RANGE_START, RANGE_END, TARGET_ADDRESS)
