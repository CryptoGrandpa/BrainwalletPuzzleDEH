"""
Multi-process range scanner. Splits the keyspace across CPU cores,
each worker uses incremental point addition within its own chunk.
"""
import hashlib
import time
import multiprocessing as mp
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

def worker(start: int, end: int, target: str, found_event, result_queue, worker_id: int):
    curve = ecdsa.SECP256k1
    generator = curve.generator
    point = start * generator  # one cold-start multiplication for this chunk

    priv_int = start
    count = 0
    t0 = time.time()

    while priv_int <= end:
        if found_event.is_set():
            return  # another worker already found it

        pubkey_compressed = compressed_pubkey_from_point(point)
        address = pubkey_to_address(pubkey_compressed)
        count += 1

        if address == target:
            found_event.set()
            result_queue.put((priv_int, address, count, time.time() - t0))
            return

        if count % 20000 == 0:
            elapsed = time.time() - t0
            rate = count / elapsed
            print(f"[worker {worker_id}] {count} keys checked ({rate:.0f} keys/sec)")

        point = point + generator
        priv_int += 1

    result_queue.put(None)  # this worker found nothing

def split_range(start: int, end: int, num_workers: int):
    total = end - start + 1
    chunk_size = total // num_workers
    chunks = []
    for i in range(num_workers):
        chunk_start = start + i * chunk_size
        chunk_end = (start + (i + 1) * chunk_size - 1) if i < num_workers - 1 else end
        chunks.append((chunk_start, chunk_end))
    return chunks

if __name__ == "__main__":
    num_workers = 4  # physical cores only, avoiding hyperthread contention
    print(f"Using {num_workers} worker processes")
    print(f"Scanning {RANGE_END - RANGE_START + 1} keys for {TARGET_ADDRESS}")

    chunks = split_range(RANGE_START, RANGE_END, num_workers)
    found_event = mp.Event()
    result_queue = mp.Queue()

    processes = []
    t0 = time.time()
    for i, (chunk_start, chunk_end) in enumerate(chunks):
        p = mp.Process(
            target=worker,
            args=(chunk_start, chunk_end, TARGET_ADDRESS, found_event, result_queue, i)
        )
        processes.append(p)
        p.start()

    # Wait for the first real result (match) to arrive
    result = None
    for _ in range(num_workers):
        r = result_queue.get()
        if r is not None:
            result = r
            break

    for p in processes:
        p.terminate()
        p.join()

    elapsed = time.time() - t0
    if result:
        priv_int, address, local_count, local_elapsed = result
        print(f"\nMATCH FOUND in {elapsed:.2f}s total")
        print(f"Private key (hex): {hex(priv_int)}")
        print(f"Private key (int): {priv_int}")
        print(f"Address: {address}")
    else:
        print("No match found in range.")
