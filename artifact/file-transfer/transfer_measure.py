import subprocess
from datetime import datetime
import re
import time
import os
import csv
import glob

HOST_MAP = {
    "127.0.0.1": {
        # "rsync_ssh_reno": {  # This key can also be "rsync_ssh_cubic"
        #     "user": "root",
        #     "protocol": "ssh"
        # },
        "rsync_hop": {
            "user": "user",
            "config": "containers/client_config.toml",
            "protocol": "hop"  # either hop or ssh in lowercase
        }
    },
}

RESULTS_FILE = "transfer_data_local.csv"
FILE_NAMES = ["100MB_file", "10MB_file", "1GB_file"]
HOP_PATH = "go run hop.computer/hop/cmd/hop"
EXPERIMENT = 10  # Will perform 10 times the experiment


def extract_speed(rsync_output):
    if "closed" in rsync_output.lower() or "error" in rsync_output.lower():
        print(rsync_output)
        return 0.0001

    # Match kB/s or MB/s
    matches = re.findall(r'(\d+\.\d+)\s*([kM])B/s', rsync_output)
    if not matches:
        return 0.0

    value, unit = matches[-1]
    value = float(value)

    if unit == "k":
        value /= 1000.0  # kB/s → MB/s

    return value


def log_result_entry(host, file_size, proto, speed, filename=RESULTS_FILE):
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="") as f:
        writer = csv.writer(f)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not file_exists:
            writer.writerow(["Time", "Host", "File Size", "Protocol", "Speed (MB/s)"])

        writer.writerow([timestamp, host, file_size, proto, speed])

    print(f"Logged: {host}, {file_size}, {proto}: {speed:.2f} MB/s")


def test_transfer(host, file_size, protocol_key):
    print(f"Testing {protocol_key} on {host} with {file_size}...")

    user = HOST_MAP[host][protocol_key]["user"]
    protocol = HOST_MAP[host][protocol_key]["protocol"]

    if protocol == "hop":
        config_path = HOST_MAP[host][protocol_key]["config"]
        command = (
            "rsync --no-compress --info=progress2 "
            f"--rsh=\"{HOP_PATH} -C {config_path}\" "
            f"{file_size} {user}@{host}:"
        )

    elif protocol == "ssh":
        command = (
            "rsync --no-compress --info=progress2 "
            "-e \"ssh -c chacha20-poly1305@openssh.com\" "
            f"{file_size} {user}@{host}:"
        )

    else:
        print(f"Unknown protocol: {protocol}. You can only specify hop or ssh in lowercase")
        return

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=1000,
        )
        output_text = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print(f"Timeout: {protocol_key} exceeded time limit")
        return

    print(output_text)

    speed = extract_speed(output_text)
    log_result_entry(host, file_size, protocol_key, speed)

    # Cleanup remote file
    try:
        if protocol == "hop":
            config_path = HOST_MAP[host][protocol_key]["config"]
            cleanup_cmd = (
                f"{HOP_PATH} -C {config_path} "
                f"-c 'rm {file_size} && exit' {user}@{host}"
            )
        else:
            cleanup_cmd = f"ssh {user}@{host} 'rm {file_size}'"

        subprocess.run(cleanup_cmd, shell=True, timeout=60)

    except subprocess.TimeoutExpired:
        print(f"Warning: cleanup timed out for {protocol}")

    time.sleep(1)


if __name__ == "__main__":
    for file in glob.glob("/tmp/hop*"):
        os.remove(file)

    for i in range(EXPERIMENT):
        print("Run test #", i)
        for host, protocol_keys in HOST_MAP.items():
            for file_size in FILE_NAMES:
                for protocol_key in protocol_keys:
                    test_transfer(host, file_size, protocol_key)
