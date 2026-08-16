"""
Multi-process range scanner, descending from top of range to bottom.
Each worker starts at the TOP of its chunk and steps downward using
incremental point subtraction (point + (-G) each step).
"""
import hashlib
import time
import datetime
import multiprocessing as mp
import ecdsa
import base58

TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
RANGE_START = 0x400000000000100000
RANGE_END = 0x400000000000200000  # inclusive

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
    neg_generator = (-1 % order) * generator  # -G, used to step downward

    point = end * generator  # cold-start multiplication at TOP of this chunk
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

        point = point + neg_generator  # step downward
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

if __name__ == "__main__":
    num_workers = 4  # physical cores only, avoiding hyperthread contention
    total_keys = RANGE_END - RANGE_START + 1

    start_wall_time = datetime.datetime.now()
    print(f"Start time: {start_wall_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Using {num_workers} worker processes (descending within each chunk)")
    print(f"Scanning {total_keys} keys for {TARGET_ADDRESS}\n")

    chunks = split_range(RANGE_START, RANGE_END, num_workers)
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
    end_wall_time = datetime.datetime.now()

    worker_counts = {}
    while not progress_queue.empty():
        wid, c = progress_queue.get()
        worker_counts[wid] = c
    total_keys_checked = sum(worker_counts.values())
    aggregate_rate = total_keys_checked / total_elapsed if total_elapsed > 0 else 0

    print(f"End time: {end_wall_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total time to solve: {total_elapsed:.2f} seconds")
    print(f"Total keys checked (all workers combined): {total_keys_checked}")
    print(f"Aggregate throughput: {aggregate_rate:.0f} keys/sec")

    if result:
        priv_int, address, local_count, local_elapsed, worker_id = result
        print(f"\nMATCH FOUND by worker {worker_id}")
        print(f"  Worker's local count: {local_count} keys, {local_elapsed:.2f}s locally")
        print(f"Private key (hex): {hex(priv_int)}")
        print(f"Private key (int): {priv_int}")
        print(f"Address: {address}")
    else:
        print("No match found in range.")
