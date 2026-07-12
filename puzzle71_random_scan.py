"""
Randomly selects an unscanned chunk within Puzzle #71's keyspace,
scans it with the multi-process descending scanner, and records
the chunk as attempted so it's never repeated.
"""
import hashlib
import time
import random
import os
import multiprocessing as mp
import ecdsa
import base58

TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
PUZZLE_MIN = 0x400000000000000000   # 2^70, start of puzzle 71's range
PUZZLE_MAX = 0x7fffffffffffffffff   # 2^71 - 1, end of puzzle 71's range
CHUNK_SIZE = 0x100000               # 1,048,576 keys per chunk (same size used before)

LEDGER_FILE = "scanned_chunks.txt"

TOTAL_CHUNKS = (PUZZLE_MAX - PUZZLE_MIN + 1) // CHUNK_SIZE

def load_scanned_chunks():
    if not os.path.exists(LEDGER_FILE):
        return set()
    with open(LEDGER_FILE, "r") as f:
        return set(int(line.strip()) for line in f if line.strip())

def record_scanned_chunk(chunk_index: int):
    with open(LEDGER_FILE, "a") as f:
        f.write(f"{chunk_index}\n")

def pick_random_unused_chunk(scanned: set) -> int:
    while True:
        candidate = random.randint(0, TOTAL_CHUNKS - 1)
        if candidate not in scanned:
            return candidate

def chunk_bounds(chunk_index: int):
    start = PUZZLE_MIN + chunk_index * CHUNK_SIZE
    end = min(start + CHUNK_SIZE - 1, PUZZLE_MAX)
    return start, end

# --- scanning logic (same as puzzle_scan_mp_desc.py) ---

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

def worker(start: int, end: int, target: str, found_event, result_queue, worker_id: int, progress_queue):
    curve = ecdsa.SECP256k1
    generator = curve.generator
    order = curve.order
    neg_generator = (-1 % order) * generator

    point = end * generator
    priv_int = end
    count = 0
    t0 = time.perf_counter()

    while priv_int >= start:
        if found_event.is_set():
            progress_queue.put((worker_id, count))
            return

        pubkey_compressed = compressed_pubkey_from_point(point)
        address = pubkey_to_address(pubkey_compressed)
        count += 1

        if address == target:
            found_event.set()
            local_elapsed = time.perf_counter() - t0
            result_queue.put((priv_int, address, count, local_elapsed, worker_id))
            progress_queue.put((worker_id, count))
            return

        if count % 20000 == 0:
            elapsed = time.perf_counter() - t0
            rate = count / elapsed
            print(f"[worker {worker_id}] {count} keys checked ({rate:.0f} keys/sec)")

        point = point + neg_generator
        priv_int -= 1

    progress_queue.put((worker_id, count))
    result_queue.put(None)

def split_range(start: int, end: int, num_workers: int):
    total = end - start + 1
    chunk_size = total // num_workers
    chunks = []
    for i in range(num_workers):
        chunk_start = start + i * chunk_size
        chunk_end = (start + (i + 1) * chunk_size - 1) if i < num_workers - 1 else end
        chunks.append((chunk_start, chunk_end))
    return chunks

def scan_chunk(range_start: int, range_end: int, num_workers: int = 4):
    total_keys = range_end - range_start + 1
    print(f"Scanning {total_keys} keys for {TARGET_ADDRESS}")
    print(f"Range: {hex(range_start)} to {hex(range_end)}\n")

    chunks = split_range(range_start, range_end, num_workers)
    found_event = mp.Event()
    result_queue = mp.Queue()
    progress_queue = mp.Queue()

    processes = []
    t0 = time.perf_counter()
    for i, (chunk_start, chunk_end) in enumerate(chunks):
        p = mp.Process(
            target=worker,
            args=(chunk_start, chunk_end, TARGET_ADDRESS, found_event, result_queue, i, progress_queue)
        )
        processes.append(p)
        p.start()

    result = None
    for _ in range(num_workers):
        r = result_queue.get()
        if r is not None:
            result = r
            break

    for p in processes:
        p.terminate()
        p.join()

    total_elapsed = time.perf_counter() - t0

    worker_counts = {}
    while not progress_queue.empty():
        wid, c = progress_queue.get()
        worker_counts[wid] = c
    total_keys_checked = sum(worker_counts.values())
    aggregate_rate = total_keys_checked / total_elapsed if total_elapsed > 0 else 0

    print(f"\nTotal time: {total_elapsed:.2f} seconds")
    print(f"Total keys checked: {total_keys_checked}")
    print(f"Aggregate throughput: {aggregate_rate:.0f} keys/sec")

    if result:
        priv_int, address, local_count, local_elapsed, worker_id = result
        print(f"\n*** MATCH FOUND by worker {worker_id} ***")
        print(f"Private key (hex): {hex(priv_int)}")
        print(f"Private key (int): {priv_int}")
        print(f"Address: {address}")
        return priv_int
    else:
        print("No match found in this chunk.")
        return None

if __name__ == "__main__":
    print(f"Total chunks in puzzle #71 keyspace: {TOTAL_CHUNKS}")

    scanned = load_scanned_chunks()
    print(f"Chunks already scanned: {len(scanned)}")

    chunk_index = pick_random_unused_chunk(scanned)
    range_start, range_end = chunk_bounds(chunk_index)

    print(f"Selected chunk #{chunk_index} (random, unused)")
    print(f"  Range: {hex(range_start)} to {hex(range_end)}\n")

    result = scan_chunk(range_start, range_end)

    record_scanned_chunk(chunk_index)
    print(f"\nChunk #{chunk_index} recorded as scanned.")
    print(f"Total chunks scanned so far: {len(scanned) + 1}")
