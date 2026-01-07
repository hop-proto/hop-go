# Artifacts Functional

---

Hop can be used in different configurations: as a standalone server, with multiple servers, or as a chain of servers, with or without hidden mode. To explore the different arrangements and configurations, please refer to [CONTAINERS](../containers/README.md).

As a mirror of the containers README, you can locally run a single Hop server in Docker as follows:

From the `hop-go` directory, run the following commands:
- `make serve-dev` to launch the docker image
- `go run hop.computer/hop/cmd/hop -C containers/client_config.toml user@127.0.0.1:7777`
  to connect to the server

# Results Reproduced

## Session Establishment

---

This experiment measures the time required to establish a non-interactive shell and execute an initial command.

All collected data reported in the paper can be found in `tts_data.csv`, and you can reproduce the plot using `tts_plot.py`.

The experiment script can be found in `tts_measure.py`.

See and update the experiment configuration at the top of the file

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
```
This configuration specify that the script must be run from the root directory of `hop-go` and requires three running servers: SSH, Hop, and Hop with hidden mode enabled.

To run it locally you can use `make cred-gen` from the project root, as described in [CONTAINERS](../containers/README.md), and then run:
- `make serve-dev` to launch the Hop server Docker container
- `make serve-dev-hidden` to launch the hidden-mode Hop server Docker container

To run it on separate machine, you must install Hop and SSH on it and  follow the instructions to configure Hop in [CONFIGURATION](../CONFIGURATION.md).

> Note
> Remember to update the measurement Python script accordingly to point to the correct IP, protocol, and configuration file paths for both hidden and discoverable modes.

`tts_plot.py` can be used to generate the bar plot showing your results similarly to the figure in the paper.
Make sure to update `RESULTS_FILE = "tts_data.csv"` to match your dataset file.


## File Transfer Speed
### In Simulation

---

This experiment runs in Mininet TODO add a link as a controlled simulation environment to isolate the effects of network variation.

You need to have a working loopback ssh authentication.
For Hop, you need to generate a client_config.toml and a server_config.toml to enable the connection to `root@10.0.3.10`

Find help in [CONFIGURATION](../CONFIGURATION.md).

TODO maybe i can easily make certificate for this sim 

### Real World

This experiment measures the time required for a file to be transferred to a remote host tunneled by different protocol.

All collected data can be found in `transfer.csv`, and you can plot it using `transfer_plot.py`. This script reproduces the results reported in the paper.

You can also measure your own transfers.

To do so you first must have running and accessible ssh or/and Hop servers. If you decide to setup environments on remote servers we suggest you to follow the instructions in [CONFIGURATION](../CONFIGURATION.md). You can also run it locally by setting up a docker environment as described in [CONTAINERS](../containers/README.md).

You then need to generate files of random data with different sizes. You can do it with the following command
```sh
dd if=/dev/urandom of=1GB_file bs=1M count=1024
dd if=/dev/urandom of=100MB_file bs=1M count=100
dd if=/dev/urandom of=10MB_file bs=1M count=10 
```

At the top of the transfer_measure.py file, edit the parameters with the according ones:

```python
HOST_MAP = {
    "127.0.0.1": {
        "rsync_ssh_cubic": {
            "user": "root",
        },
        "rsync_hop": {
            "user": "user",
            "config": "containers/client_config.toml"
        }
    },
}

RESULTS_FILE = "transfer_data_local.csv"
FILE_NAMES = ["100MB_file", "10MB_file", "1GB_file"]
HOP_PATH = "go run hop.computer/hop/cmd/hop"
```

If you want to change your congestion control to NewReno instead of cubic

`sysctl net.ipv4.tcp_congestion_control=reno`

This would reflect in your measurement key as `rsync_ssh_reno`

You can then run the measurement script and plot the results. 

Repetitive transfer of large files might take time and ressources. Please take the necessary precaution before running this experiment.

## Keystroke Latency

This experiment requires to establish a Hop or SSH session and run the typometer software. The software will record all your data and you can save if in the csv file format. Then you can print your result using our `keystrokes_plot.py` to have the visualisation of your data.

We provide a copy of the software and its licence in the keystroke-latency folder. Please refer to its readme to run the software.

All our data used in the paper can be found in `keystrockes_data.csv` and you can replicate our figure using the script `keystrokes_plot.py`.

Update the source file and the styles to have an output.


