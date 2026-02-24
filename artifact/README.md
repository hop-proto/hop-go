# Artifacts Available

In accordance with the USENIX Security Open Science Policy, we have made Hop permanently and publicly available via Zenodo at [10.5281/zenodo.17953396](https://doi.org/10.5281/zenodo.17953396).

```
hop-go
├── artifact
│   ├── file-transfer
│   ├── keystroke-latency
│   ├── simulation
│   ├── time-to-shell
│   └── README.md
└── ... hop-go source code
```

# Required Dependencies

## Hardware

To ensure correct building and execution of our experiments, we recommend using at least two machines (physical or virtual), each with a minimum of 2 vCPUs, 4 GB of RAM, and 8 GB of storage.

## Software

To run all the experiments, you will need a Linux-based machine. We suggest using `Ubuntu 24.04 LTS` with the following dependencies:

- `Golang v1.23`, for running and building Hop. Installation available at https://go.dev.  

- `Docker v28`, for building test environments. Installation available at https://docs.docker.com

- `Python3`, for evaluation only. Installation available at https://www.python.org.  

- `OpenSSH v9.7p1`, for evaluation baseline. Installation available at https://www.openssh.org.  

- `Rsync v3.3`, for file transfer. Installation available at https://github.com/RsyncProject/rsync.  

- `GNU Make v3.81`, for script automation. Installation available at https://www.gnu.org/software/make.  

- `Mininet v2.3.0`, for the evaluation in simulation. Installation available at https://mininet.org.  

- `Java 11`, to run Typometer software, only used for keystroke timing evaluation.  
  Installation available at https://www.oracle.com/java/technologies/javase/jdk11-archive-downloads.html.  

If you're using the apt package manager, you can install most of the dependencies required for the Hop artifact by executing:

```bash
apt install golang
apt install python3
apt install openssh-client openssh-server
apt install rsync
apt install make
apt install mininet
apt install openjdk-11-jre
```

Note that Docker is not installed with this command set.

> [!NOTE]
> To ensure proper execution of Hop, we recommend using `Go 1.23` for the project, as an issue with Hop's use of `creack/pty` may prevent a shell from opening when running on newer versions of Go.


# Artifacts Functional

Hop supports multiple deployment configurations: a standalone server, multiple independent servers, or chained servers, with or without hidden mode enabled. Further descriptions of supported configurations and deployment options are provided in [CONTAINERS](../containers/README.md).

To mirror the setup described in the containers documentation, a single Hop server can be run locally using Docker as follows.

From the `hop-go` directory, execute:
- `make cred-gen` to generate the default credentials for the containers
- `make serve-dev` to launch the Hop Docker container
- `go run hop.computer/hop/cmd/hop -C containers/client_config.toml user@127.0.0.1:7777`
  to connect to the server

>[!NOTE]
> If you have `io.Copy(tube, f) stopped with error: read /dev/ptmx: input/output error` Restarting the container fixes this issue.

---

# Results Reproduced

> [!WARNING]
> Most of the paths within the measurement scripts are relative to the root of the repository. You can adapt the paths to your environment.

## Session Establishment

[5 human-minutes + 20 computer-minutes]

This experiment measures the time required to establish a non-interactive shell session and execute an initial command.

All data reported in the paper are available in `tts_data.csv`. The corresponding plot can be reproduced using `tts_plot.py`.

The measurement script is located in `tts_measure.py`. The experiment configuration is defined at the top of the file:

```python
CONFIG_MAP = {
    "127.0.0.1": {
        "ssh": {
            "user": "root",
        },
        "hop-hidden": {
            "user": "user",
            "config": "containers/hidden_server/client_config_hidden.toml"
        },
        "hop": {
            "user": "user",
            "config": "containers/client_config.toml"
        }
    },
}

RESULTS_FILE = "tts_data_local.csv"
HOSTS = CONFIG_MAP.keys()
HOP_PATH = "go run hop.computer/hop/cmd/hop"
EXPERIMENT = 10  # Will perform 10 times the experiment
```

This configuration assumes execution from the root directory of `hop-go` and requires three running services: an SSH server, a Hop server, and a Hop server with hidden mode enabled.

To reproduce the experiment locally:
1. Generate credentials using `make cred-gen` from the project root (see [CONTAINERS](../containers/README.md)).
2. Launch the Hop server container using `make serve-dev`.
3. Launch the hidden-mode Hop server container using `make serve-dev-hidden`.

To run the experiment on a remote machine, install both Hop and SSH and configure Hop as described in [CONFIGURATION](../CONFIGURATION.md).

> [!NOTE] 
> The measurement script must be updated to reflect the correct IP addresses, protocols, and configuration file paths for both hidden and discoverable modes.

By default, the `tts_measure.py` is configured to run 10 measures for each of the configured protocols. Our collected dataset outlines 100 measurements for each configuration.

Use `tts_plot.py` to generate the bar plot corresponding to the figure reported in the paper. Ensure that `RESULTS_FILE` matches the dataset being plotted.

---

## File Transfer Speed

We evaluate Hop's congestion control by performing a file transfer of three different sizes: 10 MB, 100 MB, and 1 GB. Files are named following the convention `{size}_file` (e.g., `10MB_file`).

To avoid unintended compression or caching effects, all files are populated with random data:
```shell
dd if=/dev/urandom of=1GB_file bs=1M count=1024  
dd if=/dev/urandom of=100MB_file bs=1M count=100  
dd if=/dev/urandom of=10MB_file bs=1M count=10
```

Ensure that the files do not exist on the remote host before starting the file transfer; rsync will not perform it again.

Repeated transfers of large files may consume significant time and system resources. Users should take appropriate precautions before running these experiments.

> [!NOTE]
> Since Hop tubes tend not to close properly after a file transfer, we enforce their closure by forcing a `data timeout`on the client side. This can be updated in the script by finding the `--datatimeout` flag and can be configured in the `config.toml` files `DataTimeout = "3m"` for 3 minutes (as an example).


### Simulation Environment

[15 human-minutes + 15 computer-minutes]

This experiment is conducted using [Mininet](https://mininet.org/) to provide a controlled environment and isolate the effects of network conditions along the `(hop client) h1 --- r --- h3 (hop server)` path.

Script to generate credentials and Hop configuration files are available in `artifact/simulation/config`.

Key simulation parameters can be adjusted at the top of the experiment script:

```python
QUEUE = 200  
DELAYH1 = '10ms'      # h1--r link  
BWH1 = 100            # h1--r link

RESULTS_FILE = "results_hop_local.csv"  
FILE_SIZES = ["100MB"]
HOP_PATH = "go run hop.computer/hop/cmd/hop"

NETWORKS = [
{"name": "baseline", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0}
# Additional network configurations...
]
```

Run the Mininet simulation from the `hop-go` root directory with elevated privileges (`sudo`). Be sure that Hop can also run with these privileges. You can either add go to the sudoers file or build Hop and update the script paths.

> [!WARNING]
> Be sure you have the mininet client public key in the mininet server `$(HOME_DIR)/.hop/authorized_keys`. It is usually in `/root/.hop/authorized_keys` on a Linux machine.

The script produces a dataset that can be visualized using `simulation_plot.py`. The datasets used to generate the figures in the paper are provided and can be plotted directly using the same script.

---

### Real-World Deployment

[15 human-minutes + 2 computer-hour]

This experiment measures end-to-end file transfer time to a remote host tunneled over different protocols.

All data reported in the paper are available in `transfer.csv`. The corresponding plot can be reproduced using `transfer_plot.py`.

Users may also collect new measurements. This requires running and accessible SSH and/or Hop servers. For remote deployments, follow the setup instructions in [CONFIGURATION](../CONFIGURATION.md). Alternatively, a local Docker-based setup can be used as described in [CONTAINERS](../containers/README.md).

Experiment parameters are defined at the top of `transfer_measure.py`:
```python
HOST_MAP = {
    "127.0.0.1": {
        # "rsync_ssh_reno": {  # This key can also be "rsync_ssh_cubic"
        #     "user": "root",
        #     "protocol": "ssh"
        # },
        "rsync_hop": {
            "user": "user",
            "config": "containers/client_config.toml",
            "protocol": "hop"  # either "hop" or "ssh" in lowercase
        }
    },
}

RESULTS_FILE = "transfer_data_local.csv"
FILE_NAMES = ["100MB_file", "10MB_file", "1GB_file"]
HOP_PATH = "go run hop.computer/hop/cmd/hop"
EXPERIMENT = 10  # Will perform 10 times the experiment
```

To switch the TCP congestion control algorithm from Cubic to NewReno, execute:

`sysctl net.ipv4.tcp_congestion_control=reno`

Measurements collected under this configuration will be labeled using the key `rsync_ssh_reno`.

After running the measurement script, results can be visualized using `transfer_plot.py`.

---

## Keystroke Latency

[30 human-minutes + 1 computer-hour]

This experiment measures interactive latency during terminal usage. A Hop or SSH session must be established with an interactive terminal, after which the Typometer software will require to select the active terminal window and record keystroke latency data. Results can be exported in CSV format.

A copy of the [Typometer](https://github.com/pavelfatin/typometer) software and its license is provided in the `keystroke-latency` directory. Refer to the included README for usage instructions.

All data used in the paper are available in `keystrokes_data.csv`. The corresponding figure can be reproduced using `keystrokes_plot.py`.

Users may update the input dataset and plotting parameters to customize the visualization.

> [!NOTE]
> This experiment does not have a script to run the experiments, as it is entirely handled by the Typometer software. The `typometer/` folder and all its files are a copy of the original source code accessed in August 2025.
