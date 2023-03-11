#! /bin/bash

echo -e "hop_time,ssh_time" > ./latency.csv

for i in {1..100}
do
    hop_time=$(./pty_time/pty_time ~\# ./hop -C ./containers/client_config hop://root@127.0.0.1:7777 2>/dev/null \
        | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p')

    ssh_time=$(./pty_time/pty_time ~\# ssh -i ./containers/ssh_id_ed25519 -p 7777 root@127.0.0.1 \
        | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p')
    
    echo -e "$hop_time,$ssh_time" >> ./latency.csv
done
