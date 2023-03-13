#! /bin/bash

chmod 600 ./containers/ssh_id_ed25519
export TIMEFORMAT="%3R"

output_file=throughput.csv
rm $output_file

hop_transfer_file() {
    echo -n "hop time $1 (seconds)," >> $output_file
    for i in {1..100}; do
        echo "hop $1 $i"
        { time ./hop -C ./containers/client_config \
            hop://root@127.0.0.1:7777 "cat > $1" < $1; } 2>&1 \
            | tr -d '\n' >> $output_file

        echo -n "," >> $output_file
    done
    echo "" >> $output_file
}

ssh_transfer_file() {
    echo -n "ssh time $1 (seconds)," >> $output_file
    for i in {1..100}; do
        echo "ssh $1 $i"
        { time scp -q -i ./containers/ssh_id_ed25519 -P 7777 \
            $1 root@127.0.0.1:$1; } 2>&1 \
            | tr -d '\n' >> $output_file

        echo -n "," >> $output_file
    done
    echo "" >> $output_file
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
