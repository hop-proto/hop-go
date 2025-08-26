import subprocess
from datetime import datetime
import re
import time
import os
import csv
import glob


def extract_speed(rsync_output):
    if "closed" in rsync_output.lower() or "error" in rsync_output.lower():
        print(rsync_output)
        return 0.0001

    # Match both MB/s and kB/s
    match = re.findall(r'(\d+\.\d+)([kM])B/s', rsync_output)

    if match:
        value, unit = match[-1]
        value = float(value)

        if unit == 'k':
            value = value / 1000  # convert kB/s to MB/s

        if value <= 300:
            return value


def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)


def get_config_path(host):
    config_map = {
        "XXX-1": "ny2",
        "XXX-2": "sg",
        "XXX-3": "fk"
    }

    return f"./{config_map.get(host, 'sf')}/config_hidden.toml"


def log_result_entry(host, file_size, proto, speed, filename="transfer_data.csv"):
    file_exists = os.path.isfile(filename)

    with open(filename, mode="a", newline="") as file:
        writer = csv.writer(file)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not file_exists:
            writer.writerow(["Time", "Host", "File Size", "Protocol", "Speed (MB/s)"])

        writer.writerow([timestamp, host, file_size, proto, speed])

    print(f"Logged: {host}, {file_size}, {proto}: {speed} MB/s")


def test_transfer(host, file_size):
    print(f"Testing on {host} with {file_size}...")

    run_cmd(f"ssh root@{host} 'rm {file_size}'")
    config_path = get_config_path(host)

    protocols = {
        "rsync_hop": f"rsync --no-compress --info=progress2 --rsh='./hop -C {config_path} root@{host}' {file_size} :",
        "rsync_ssh": f"rsync --no-compress --info=progress2 -e 'ssh -c chacha20-poly1305@openssh.com' {file_size} root@{host}:",
    }

    for proto, cmd in protocols.items():
        try:
            output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1000)
            output_text = output.stdout + output.stderr
        except subprocess.TimeoutExpired:
            print(f"Timeout: {proto} took longer than 2.5 minutes. Skipping to next protocol.")
            continue

        print(output_text)
        speed = extract_speed(output_text)
        log_result_entry(host, file_size, proto, speed)

        try:
            subprocess.run(f"ssh root@{host} 'rm {file_size}'", shell=True, timeout=60)
        except subprocess.TimeoutExpired:
            print(f"Warning: Cleanup command timed out for {proto}")

        time.sleep(1)


for file in glob.glob("/tmp/hop*"):
    os.remove(file)

hosts = ["XXX-1", "XXX-2", "XXX-3"]  # IP adresses
file_sizes = ["100MB_file", "10MB_file", "1GB_file"]  # Files

i = 0
for i in range(0, 100):
    i += 1
    for host in hosts:
        for file in file_sizes:
            test_transfer(host, file)
