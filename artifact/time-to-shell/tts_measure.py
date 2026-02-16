import time
import sys
import subprocess
from datetime import datetime
import glob
import os

CONFIG_MAP = {
    "127.0.0.1": {
        # Uncomment to enable the measure of SSH on the specified IP
        # "ssh": {
        #    "user": "root",
        # },
        "hop-hidden": {
            "user": "user",
            "config": "containers/hidden_server/client_config_hidden.toml"  # update this with the config paths
        },
        "hop": {
            "user": "user",
            "config": "containers/client_config.toml"  # update this with the config paths
        }
    },
}

RESULTS_FILE = "tts_data_local.csv"
HOSTS = CONFIG_MAP.keys()
HOP_PATH = "go run hop.computer/hop/cmd/hop"  # Update this with the actual path to the hop binary
EXPERIMENT = 10  # Will perform 10 times the experiment


def run_command(cmd):
    start_time = time.time()
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        while time.time() - start_time < 20:
            output = process.stdout.readline()
            if "Connected" in output:
                duration = time.time() - start_time
                process.kill()
                print("success")
                return duration

        process.kill()

    except Exception as e:
        print(f"Error running command: {e}")

    return 0  # unsuccessful


def test_connection(protocol, host):
    if protocol != "ssh":
        config_path = CONFIG_MAP[host][protocol]["config"]
    else:
        config_path = ""

    user = CONFIG_MAP[host][protocol]["user"]

    commands = {
        "hop": f"{HOP_PATH} -C {config_path} -c 'echo Connected && exit' {user}@{host}",
        "hop-hidden": f"{HOP_PATH} -C {config_path} -c 'echo Connected && exit' {user}@{host}",
        "ssh": f"ssh -c chacha20-poly1305@openssh.com {user}@{host} 'echo Connected && exit'"
    }

    return run_command(commands[protocol])


def log_results(protocol, duration, host, log_number):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp};{protocol};{duration};{host};{log_number}\n"

    with open(RESULTS_FILE, "a") as file:
        file.write(log_entry)


def run_tests(log_number):
    for host, protocols in CONFIG_MAP.items():

        for key in protocols.keys():

            if key == "ssh":
                print("Run SSH")
                duration = test_connection("ssh", host)
                log_results("SSH", duration, host, log_number)

            elif key == "hop-hidden":
                print("Run Hop Hidden")
                duration = test_connection("hop-hidden", host)
                log_results("Hop Hidden", duration, host, log_number)

            elif key == "hop":
                print("Run Hop")
                duration = test_connection("hop", host)
                log_results("Hop", duration, host, log_number)

            else:
                print(f"Unknown protocol: {key}")

            time.sleep(1)


if __name__ == "__main__":
    for file in glob.glob("/tmp/hop*"):
        os.remove(file)

    log_number = sys.argv[1] if len(sys.argv) > 1 else "default"

    for i in range(EXPERIMENT):
        print("Run test #", i)
        run_tests(log_number)
