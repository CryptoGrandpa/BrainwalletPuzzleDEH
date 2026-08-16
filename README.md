This is a Python 7 bitshift version of scanning keys for the Puzzle71 public BTC address
1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
using each numeric value to check each numeric value by converting to a private key and returning
the public BTC address and comparin to the public address which contains the BTC for the puzzle
winner to claim.

This bitshift version looks only at addresses with between 9 and 19 "1" values in the initial
x number of bits. This is a publicly accessible tactic if you go to a BTC Puzzle mining website and it 
was created to reduce the number of keys to scan based on the fact that more than 40 of the 70 solved 
puzzles has between 9 and 19 "1" values in the initial number of bits.

TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
PUZZLE_MIN = 0x400000000000000000   # 2^70, start of puzzle 71's range
PUZZLE_MAX = 0x7fffffffffffffffff   # 2^71 - 1, end of puzzle 71's range
CHUNK_SIZE = 0x100000               # 1,048,576 keys per chunk (same size used before)
PREFIX_SHIFT = 44     # bits below the 7-hex-digit prefix (18 hex digits - 7 = 11 hex digits = 44 bits)
MIN_ONES = 9
MAX_ONES = 19
LEDGER_FILE = "scanned_chunks.txt"
TOTAL_CHUNKS = (PUZZLE_MAX - PUZZLE_MIN + 1) // CHUNK_SIZE

This is designed to work on an eight-core CPU (not a GPU) and uses 4 cores at a time.
Estimated time on an old Microsoft Surface Pro laptop is about 28 to 40 seconds to process 
1,048,576 keys per chunk.

The difference between using this and using a "pool" to secure a new chunk to process is that solo
mining with a CPU doesn't give you the ability to secure and validate an unused chunk. To do that you need
an nVidia GPU and have to use the mining website's code and you have to use the GPU to validate some randomized
values and report back the findings to prove you processed the "chunk" they provided to get your next "chunk"
to scan.

So.... this simple script uses a different tactic and pulls chunks in a RANDOM manner and stores the chunk 
information in a plain text file so it does not check the chunks of 1,048,576 keys that were already processed.
I can overwrite the file scanned_chunks.txt containing the chunks processed to the github address if anyone actually 
wants to play around and access the current list of scanned chunks and only scan those I haven't scanned yet.

