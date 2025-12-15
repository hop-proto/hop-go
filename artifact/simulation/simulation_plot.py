import matplotlib.pyplot as plt
import csv
from collections import defaultdict
from datetime import datetime

ssh_file = "./results_ssh.csv"
hop_file = "./results_hop.csv"

# Load and tag data
def load_results(filename, label):
    results = []
    with open(filename, 'r') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            try:
                _, size, test_type, bw, delay, jitter, loss, speed, _ = row
                results.append({
                    "label": label,
                    "Bandwidth (Mb/s)": float(bw),
                    "Delay (ms)": int(delay.replace('ms', '')),
                    "Jitter (ms)": int(jitter.replace('ms', '')),
                    "Loss (%)": float(loss),
                    "speed": float(speed)
                })
            except Exception as e:
                print(f"Skipping row in {label}: {e}")
    return results

ssh_data = load_results(ssh_file, "SSH")
hop_data = load_results(hop_file, "Hop")
all_data = ssh_data + hop_data


seen = set()
unique_data = []
for row in all_data:
    row_tuple = (row["label"], row["Bandwidth (Mb/s)"], row["Delay (ms)"],
                 row["Jitter (ms)"], row["Loss (%)"])
    if row_tuple not in seen:
        seen.add(row_tuple)
        unique_data.append(row)

all_data = unique_data


def find_line_groups(data):
    groups = []
    keys = ['Bandwidth (Mb/s)', 'Delay (ms)', 'Jitter (ms)', 'Loss (%)']
    
    for varying in keys:
        fixed_keys = [k for k in keys if k != varying]
        
        temp = defaultdict(list)
        for row in data:
            key = tuple((k, row[k]) for k in fixed_keys)
            temp[key].append(row)
        
        for fixed_key, rows in temp.items():
            varying_vals = set(r[varying] for r in rows)
            if len(varying_vals) < 2:
                continue

            combo_check = defaultdict(set)
            for r in rows:
                combo_check[r[varying]].add(r["label"])
            if not all({"SSH", "Hop"}.issubset(v) for v in combo_check.values()):
                continue

            groups.append({
                "varying": varying,
                "fixed": dict(fixed_key),
                "rows": rows
            })
    return groups

line_groups = find_line_groups(all_data)

# Plot
fig, axs = plt.subplots(2, 2, figsize=(10, 5))


axs = axs.flatten()
plotted = 0

for group in line_groups:
    if plotted >= len(axs):
        break

    varying = group["varying"]
    rows = group["rows"]
    fixed = ", ".join(f"{k}={int(v)}" for k, v in group["fixed"].items())


    ssh_points = sorted((r[varying], r["speed"]) for r in rows if r["label"] == "SSH")
    hop_points = sorted((r[varying], r["speed"]) for r in rows if r["label"] == "Hop")

    x_ssh, y_ssh = zip(*ssh_points)
    x_hop, y_hop = zip(*hop_points)

    ax = axs[plotted]
    ax.plot(x_ssh, y_ssh, '-o', label='SSH', color='#5ec962')
    ax.plot(x_hop, y_hop, '-x', label='Hop', color='#3b528b')
    ax.set_xlabel(varying, fontsize=15)
    ax.set_ylabel("Throughput (MB/s)", fontsize=13)
    ax.set_ylim(0, 13)
    ax.legend()
    ax.grid(True)
    plotted += 1

# Remove empty plots
for i in range(plotted, len(axs)):
    fig.delaxes(axs[i])

fig.tight_layout(rect=[0, 0.03, 1, 0.95])
today = datetime.today().strftime("%Y-%m-%d")
filename = f"simulation_{today}.pdf"
plt.savefig(filename)
plt.show()

