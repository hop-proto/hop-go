import time
import sys
import subprocess
from datetime import datetime
import glob
import os

CONFIG_MAP = {
    "XXX-1": "ny2",
    "XXX-2": "sg",
    "XXX-3": "fk"
}

RESULTS_FILE = "tts_data.csv"
HOSTS = CONFIG_MAP.keys()
HOP_PATH = "../../hop"  # Update this with the actual path to the hop binary


def get_config_path(host, hidden=False):
    config_filename = "config_hidden.toml" if hidden else "config.toml"
    return f"/{CONFIG_MAP.get(host, 'sg')}/{config_filename}" # Update this with the config path


def run_command(cmd):
    start_time = time.time()
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
    return 0  # Return 0 if the connection was unsuccessful


def test_connection(protocol, host, hidden=False):
    config_path = get_config_path(host, hidden)
    commands = {
        "hop": f"{HOP_PATH} -C {config_path} -c 'echo Connected && exit' root@{host}",
        "ssh": f"ssh -c chacha20-poly1305@openssh.com root@{host} 'echo Connected && exit'"
    }
    return run_command(commands[protocol])


def log_results(protocol, duration, host, log_number):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp};{protocol};{duration};{host};{log_number}\n"
    with open(RESULTS_FILE, "a") as file:
        file.write(log_entry)


def run_tests(log_number):
    for host in HOSTS:

        hidden = True
        if hidden:
            hop_hidden_duration = test_connection("hop", host, hidden=True)
            log_results("Hop Hidden", hop_hidden_duration, host, log_number)

        else:
            print("Run SSH")
            ssh_duration = test_connection("ssh", host)
            log_results("SSH", ssh_duration, host, log_number)

            print("Run Hop")
            hop_duration = test_connection("hop", host, hidden=False)
            log_results("Hop", hop_duration, host, log_number)

        time.sleep(1)


if __name__ == "__main__":
    for file in glob.glob("/tmp/hop*"):
        os.remove(file)

    log_number = sys.argv[1] if len(sys.argv) > 1 else "default"

    i = 0
    for i in range(0, 100):
        print("Run test #", i)
        run_tests(log_number)
        i += 1

