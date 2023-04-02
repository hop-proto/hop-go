#! /bin/bash

chmod 600 ./containers/ssh_id_ed25519
export TIMEFORMAT="%3R"

hop_output=hop_throughput.csv
ssh_output=ssh_throughput.csv

echo -e "file size (bytes),time to transfer (microseconds)" > $hop_output
echo -e "file size (bytes),time to transfer (microseconds)" > $ssh_output

filename_to_bytes() {
    du -b $1 | cut -f 1
}

# takes in the name of a file to transfer
hop_transfer_file() {
    size=$(filename_to_bytes $1)
    for i in {1..100}; do
        echo "hop $1 $i"
        echo -n "$size," >> $hop_output
        ./pty_time/pty_time matches \
            bash -c "./hop -C ./containers/client_config $2 \"cat $1 && echo 'done echoing file'\" | grep -m 1 \"done echoing file\"" \
            | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p' \
            >>$hop_output
    done
}

# takes in the name of a file to transfer
ssh_transfer_file() {
    size=$(filename_to_bytes $1)
    for i in {1..100}; do
        echo "ssh $1 $i"
        echo -n "$size," >> $ssh_output
        ./pty_time/pty_time matches \
            bash -c "ssh -i ./containers/ssh_id_ed25519 $2 \"cat $1 && echo 'done echoing file'\" | grep -m 1 \"done echoing file\"" \
            | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p' \
            >>$ssh_output
    done
}

hop_transfer_file 1kB_file $1
ssh_transfer_file 1kB_file $1

hop_transfer_file 1MB_file $1
ssh_transfer_file 1MB_file $1

#hop_transfer_file 100MB_file $1
#ssh_transfer_file 100MB_file $1

#hop_transfer_file 1GB_file $1
#ssh_transfer_file 1GB_file $1
