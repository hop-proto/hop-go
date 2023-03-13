#! /bin/bash


hop_output=hop_rtt_vs_latency.csv
ssh_output=ssh_rtt_vs_latency.csv

echo -e "rtt (microseconds),time to shell (microseconds)" > $hop_output
echo -e "rtt (microseconds),time to shell (microseconds)" > $ssh_output

change_latency() {
    echo "" | \
    ./hop -C ./containers/client_config \
        hop://root@127.0.0.1:7777 "tc qdisc replace dev eth0 root netem delay $1"
}

# takes in an rtt in microseconds as an argument
hop_measure_latency() {
    change_latency "$1usecs"
    for i in {1..100}; do
        echo "hop $1 $i"
        echo -n "$1," >> $hop_output
        ./pty_time/pty_time "~#" ./hop -C ./containers/client_config \
            hop://root@127.0.0.1:7777 2>/dev/null \
            | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p' \
            >> $hop_output
    done
}

# takes in an rtt in microseconds as an argument
ssh_measure_latency() {
    change_latency $1
    for i in {1..100}; do
        echo "ssh $1 $i"
        echo -n "$1," >> $ssh_output
        ./pty_time/pty_time "~#" ssh -i ./containers/ssh_id_ed25519 -p 7777 \
            root@127.0.0.1 2>/dev/null \
            | sed -nr 's/diff: ([[:digit:]]+) microseconds/\1/p' \
            >> $ssh_output
    done
}

hop_measure_latency 0
ssh_measure_latency 0

hop_measure_latency 1
ssh_measure_latency 1

hop_measure_latency 10
ssh_measure_latency 10

hop_measure_latency 100
ssh_measure_latency 100

# 1 millisecond
hop_measure_latency 1000
ssh_measure_latency 1000

# 10 ms
hop_measure_latency 10000
ssh_measure_latency 10000

# 20 ms
hop_measure_latency 20000
ssh_measure_latency 20000

# 50 ms
hop_measure_latency 50000
ssh_measure_latency 50000

# 100 ms
hop_measure_latency 100000
ssh_measure_latency 100000

# 200 ms
hop_measure_latency 200000
ssh_measure_latency 200000

# 500 ms
hop_measure_latency 500000
ssh_measure_latency 500000

# 1000 ms
hop_measure_latency 1000000
ssh_measure_latency 1000000
