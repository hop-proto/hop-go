#! /bin/bash

echo -e "hop_time,ssh_time" > ./latency.csv

for i in {1..100}
do
    echo "hop iteration $i"
    hop_time=$(./pty_time/pty_time $ ./hop -C ./containers/client_config $1 2>/dev/null \
        | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p')

    echo "ssh iteration $i"
    ssh_time=$(./pty_time/pty_time $ ssh -i ./containers/ssh_id_ed25519 $1 \
        | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p')
    
    echo -e "$hop_time,$ssh_time" >> ./latency.csv
done
