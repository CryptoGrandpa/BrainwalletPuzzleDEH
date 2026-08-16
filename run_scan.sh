#!/bin/bash
while true; do
    python3 puzzle71_random_scan.py 2>&1 | tee -a scan_log.txt
    status=${PIPESTATUS[0]}
    echo "----------------------------------------" | tee -a scan_log.txt
    if [ "$status" -eq 42 ]; then
        echo "MATCH FOUND — stopping scan loop." | tee -a scan_log.txt
        break
    fi
done
