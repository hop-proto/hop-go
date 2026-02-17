# Artifacts Available

In accordance with the USENIX Security Open Science Policy, we have made Hop permanently and publicly available via Zenodo at [10.5281/zenodo.17953396](https://doi.org/10.5281/zenodo.17953397).

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

## Session Establishment

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

We evaluate file transfer performance using three file sizes: 10 MB, 100 MB, and 1 GB. Files are named following the convention `{size}_file` (e.g., `10MB_file`).

To avoid unintended compression or caching effects, all files are populated with random data:
```shell
dd if=/dev/urandom of=1GB_file bs=1M count=1024  
dd if=/dev/urandom of=100MB_file bs=1M count=100  
dd if=/dev/urandom of=10MB_file bs=1M count=10
```

Repeated transfers of large files may consume significant time and system resources. Users should take appropriate precautions before running these experiments.

> [!NOTE]
> If your tubes do not close properly after a file transfer, you might need to enforce a data timeout. We suggest setting it to 15 seconds for this experiment instead of the default 15 minutes. To do so, edit `hop-go/config/config.go` in the function `func (hc *HostConfigOptional) Unwrap() *HostConfig` and set:
>
>     DataTimeout: 15 * time.Second,

### Simulation Environment

This experiment is conducted using [Mininet](https://mininet.org/) to provide a controlled environment and isolate the effects of network conditions along the `h1--r--h3` path.

Script to generate credentials and Hop configuration files are available in `artifact/simulation/config`.

Key simulation parameters can be adjusted at the top of the experiment script:

```python
QUEUE = 200  
DELAYH1 = '10ms'      # h1--r link  
BWH1 = 100            # h1--r link

RESULTS_FILE = "results_hop_local.csv"  
FILE_SIZES = ["100MB"]

NETWORKS = [
{"name": "baseline", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0}
# Additional network configurations...
]
```

Run the Mininet simulation from the `hop-go` root directory with elevated privileges (`sudo`).

> [!WARNING]
> Be sure you have the mininet client public key in the mininet server `$(HOME_DIR)/.hop/authorized_keys`. It is usually in `/root/.hop/authorized_keys` on Linux machine.

The script produces a dataset that can be visualized using `simulation_plot.py`. The datasets used to generate the figures in the paper are provided and can be plotted directly using the same script.

---

### Real-World Deployment

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

This experiment measures interactive latency during terminal usage. A Hop or SSH session must be established with an interactive terminal, after which the Typometer software will require to select the active terminal window and record keystroke latency data. Results can be exported in CSV format.

A copy of the [Typometer](https://github.com/pavelfatin/typometer) software and its license is provided in the `keystroke-latency` directory. Refer to the included README for usage instructions.

All data used in the paper are available in `keystrokes_data.csv`. The corresponding figure can be reproduced using `keystrokes_plot.py`.

Users may update the input dataset and plotting parameters to customize the visualization.

> [!NOTE]
> This experiment does not have a script to run the experiments as it is entirely handled by the Typometer software.
