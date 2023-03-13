#! /bin/bash

chmod 600 ./containers/ssh_id_ed25519
export TIMEFORMAT="%3R"

hop_output=hop_throughput.csv
ssh_output=ssh_throughput.csv

echo -e "file size (bytes),time to transfer (seconds)" > $hop_output
echo -e "file size (bytes),time to transfer (seconds)" > $ssh_output

filename_to_bytes() {
    du -b $1 | cut -f 1
}

# takes in the name of a file to transfer
hop_transfer_file() {
    size=$(filename_to_bytes $1)
    for i in {1..100}; do
        echo "hop $1 $i"
        echo -n "$size," >> $hop_output
        { time ./hop -C ./containers/client_config \
            hop://root@127.0.0.1:7777 "cat > $1" < $1; } \
            2>>$hop_output
    done
}

# takes in the name of a file to transfer
ssh_transfer_file() {
    size=$(filename_to_bytes $1)
    for i in {1..100}; do
        echo "ssh $1 $i"
        echo -n "$size," >> $ssh_output
        { time scp -q -i ./containers/ssh_id_ed25519 -P 7777 \
            $1 root@127.0.0.1:$1; } \
            2>>$ssh_output
    done
}

hop_transfer_file 1kB_file
ssh_transfer_file 1kB_file

hop_transfer_file 1MB_file
ssh_transfer_file 1MB_file

hop_transfer_file 100MB_file
ssh_transfer_file 100MB_file

hop_transfer_file 1GB_file
ssh_transfer_file 1GB_file

hop_transfer_file 10GB_file
ssh_transfer_file 10GB_file
