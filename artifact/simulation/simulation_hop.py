import re
from datetime import datetime
from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel, info

QUEUE = 200
DELAYH1 = '10ms'      # h1--r link
BWH1 = 100            # h1--r link

RESULTS_FILE = "results_hop_local.csv"
FILE_SIZES = ["100MB"]

NETWORKS = [
    # === BASELINE ===
    {"name": "baseline", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0},

    # === BANDWIDTH SCALING ===
    #{"name": "bw_1Mbps", "bw": 1, "delay": "10ms", "jitter": "0ms", "loss": 0},
    #{"name": "bw_5Mbps", "bw": 5, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_10Mbps", "bw": 10, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_20Mbps", "bw": 20, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_30Mbps", "bw": 30, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_40Mbps", "bw": 40, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_50Mbps", "bw": 50, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_60Mbps", "bw": 60, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_70Mbps", "bw": 70, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_80Mbps", "bw": 80, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_90Mbps", "bw": 90, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "bw_100Mbps", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0},

    # === DELAY SCALING ===
    {"name": "delay_1ms", "bw": 100, "delay": "1ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_5ms", "bw": 100, "delay": "5ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_10ms", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_20ms", "bw": 100, "delay": "20ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_50ms", "bw": 100, "delay": "50ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_100ms", "bw": 100, "delay": "100ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_200ms", "bw": 100, "delay": "200ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_300ms", "bw": 100, "delay": "300ms", "jitter": "0ms", "loss": 0},
    {"name": "delay_500ms", "bw": 100, "delay": "500ms", "jitter": "0ms", "loss": 0},
    #{"name": "delay_750ms", "bw": 100, "delay": "750ms", "jitter": "0ms", "loss": 0},
    #{"name": "delay_1000ms", "bw": 100, "delay": "1000ms", "jitter": "0ms", "loss": 0},

    # === JITTER SCALING ===
    {"name": "jitter_0ms", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "jitter_5ms", "bw": 100, "delay": "10ms", "jitter": "5ms", "loss": 0},
    {"name": "jitter_10ms", "bw": 100, "delay": "10ms", "jitter": "10ms", "loss": 0},
    {"name": "jitter_20ms", "bw": 100, "delay": "10ms", "jitter": "20ms", "loss": 0},
    {"name": "jitter_30ms", "bw": 100, "delay": "10ms", "jitter": "30ms", "loss": 0},
    {"name": "jitter_50ms", "bw": 100, "delay": "10ms", "jitter": "50ms", "loss": 0},
    {"name": "jitter_75ms", "bw": 100, "delay": "10ms", "jitter": "75ms", "loss": 0},
    {"name": "jitter_100ms", "bw": 100, "delay": "10ms", "jitter": "100ms", "loss": 0},
    {"name": "jitter_150ms", "bw": 100, "delay": "10ms", "jitter": "150ms", "loss": 0},
    {"name": "jitter_200ms", "bw": 100, "delay": "10ms", "jitter": "200ms", "loss": 0},

    # === LOSS SCALING ===
    {"name": "loss_0", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0},
    {"name": "loss_0.1", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0.1},
    {"name": "loss_0.25", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0.25},
    {"name": "loss_0.5", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0.5},
    {"name": "loss_0.75", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 0.75},
    {"name": "loss_1", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 1},
    {"name": "loss_2", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 2},
    {"name": "loss_3", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 3},
    {"name": "loss_5", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 5},
    {"name": "loss_7.5", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 7.5},
    {"name": "loss_10", "bw": 100, "delay": "10ms", "jitter": "0ms", "loss": 10},

    # === REALISTIC COMPOSITE SCENARIOS ===
    #{"name": "4G_urban", "bw": 20, "delay": "30ms", "jitter": "5ms", "loss": 0.2},
    #{"name": "4G_rural", "bw": 5, "delay": "100ms", "jitter": "20ms", "loss": 0.5},
    #{"name": "5G_ideal", "bw": 200, "delay": "5ms", "jitter": "1ms", "loss": 0.05},
    #{"name": "wifi_highload", "bw": 10, "delay": "80ms", "jitter": "40ms", "loss": 2},
    #{"name": "satellite_L1", "bw": 10, "delay": "300ms", "jitter": "30ms", "loss": 0.2},
    #{"name": "satellite_L2", "bw": 10, "delay": "600ms", "jitter": "50ms", "loss": 0.5},
    #{"name": "mobile_edge", "bw": 5, "delay": "250ms", "jitter": "20ms", "loss": 1},
    #{"name": "congested_net", "bw": 1, "delay": "300ms", "jitter": "100ms", "loss": 5},
    #{"name": "unstable_wifi", "bw": 5, "delay": "100ms", "jitter": "80ms", "loss": 3},
    #{"name": "starlink_like", "bw": 100, "delay": "50ms", "jitter": "10ms", "loss": 0.1},
]

class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        info('enabling forwarding on ', self)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class RTopo(Topo):
    def build(self, config=None, **_opts):
        r = self.addNode('r', cls=LinuxRouter)
        h1 = self.addHost('h1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
        h3 = self.addHost('h3', ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')

        self.addLink(h1, r, intfName1='h1-eth', intfName2='r-eth1', bw=BWH1,
                     params2={'ip': '10.0.1.1/24'}, delay=DELAYH1)

        self.addLink(h2, r, intfName1='h2-eth', intfName2='r-eth2', bw=80,
                     params2={'ip': '10.0.2.1/24'})

        self.addLink(h3, r, intfName1='h3-eth', intfName2='r-eth3',
                     params2={'ip': '10.0.3.1/24'},
                     bw=config["bw"],
                     delay=config["delay"],
                     loss=config["loss"],
                     jitter=config["jitter"])


def extract_speed(rsync_output, bw):
    if "closed" in rsync_output.lower() or "error" in rsync_output.lower():
        print(rsync_output)
        return 0.0001

    match = re.findall(r'(\d+\.\d+)([kM])B/s', rsync_output)

    if match:
        value, unit = match[-1]
        value = float(value)

        if unit == 'k':
            value = value / 1000

        if value <= bw:
            return value

    return 0

def run_hop_rsync(h1, file_size, bw):
    cmd = f'rsync --no-compress --info=progress2 --rsh="go run hop.computer/hop/cmd/hop -C ./artifact/simulation/config/client_config.toml --datatimeout 10s root@10.0.3.10" ./{file_size}_file :/tmp/file/'
    return run_cmd(h1, file_size, cmd, bw)



def run_cmd(h1, file_size, cmd, bw):
    output = h1.cmd(cmd)
    return extract_speed(output, bw)


def log_and_print(file, text):
    print(text)
    file.write(text + '\n')


def run_tests():
    with open(RESULTS_FILE, 'a') as file:
        for config in NETWORKS:
            topo = RTopo(config)
            net = Mininet(topo=topo, controller=None, link=TCLink, autoSetMacs=True)
            net.start()

            r = net['r']
            r.cmd('ip route list')
            r.cmd('ifconfig r-eth1 10.0.1.1/24')
            r.cmd('ifconfig r-eth2 10.0.2.1/24')
            r.cmd('ifconfig r-eth3 10.0.3.1/24')
            r.cmd('sysctl net.ipv4.ip_forward=1')
            r.cmd(f'tc qdisc change dev r-eth3 handle 10: netem limit {QUEUE}')

            h1 = net['h1']
            h2 = net['h2']
            h3 = net['h3']

            h1.cmd('tc qdisc del dev h1-eth root')
            h1.cmd('tc qdisc add dev h1-eth root fq')
            h2.cmd('tc qdisc del dev h2-eth root')
            h2.cmd('tc qdisc add dev h2-eth root fq')

            for h in [r, h1, h2, h3]:
                h.cmd('/usr/sbin/sshd')

            h3.cmd("rm -f /tmp/hop*")
            h3.cmd("rm -f /tmp/file/*")

            h3.cmd("go run hop.computer/hop/cmd/hopd -C ./artifact/simulation/config/server_config.toml &")

            for size in FILE_SIZES:
                print("-------------------------------------------------------------------")

                if "GB" in size:
                    file_size_mb = int(size.replace("GB", "")) * 1024
                elif "MB" in size:
                    file_size_mb = int(size.replace("MB", ""))

                speed = run_hop_rsync(h1, size, config["bw"])
                log_and_print(file, f"{datetime.now()};{file_size_mb};Hop;{config['bw']};{config['delay']};{config['jitter']};{config['loss']};{speed};")

            h3.cmd("rm -f /tmp/file/*")

            net.stop()

    print(f"Results saved to {RESULTS_FILE}")


# Start test
run_tests()


