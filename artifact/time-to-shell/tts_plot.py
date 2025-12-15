import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import matplotlib.cm as cm
from datetime import datetime
import matplotlib.colors as mcolors

RESULTS_FILE = "./tts-usenix-08_14.csv"

host_map = {
    "159.223.19.58": "Europe",
    "178.128.114.253": "Asia",
    "192.81.210.132": "USA"
}

def load_data():
    # Read CSV, specifying column names explicitly
    df = pd.read_csv(RESULTS_FILE, sep=';', names=['Timestamp', 'Type', 'Latency', 'IP', 'RTT'], dtype=str, on_bad_lines='skip')


    df["Type"] = df["Type"].replace({"Hop": "Hop-D", "Hop Hidden": "Hop-H"})

    # Convert 'Duration' column to numeric, force errors to NaN and drop them
    df["Latency"] = pd.to_numeric(df["Latency"], errors='coerce')
    df["RTT"] = pd.to_numeric(df["RTT"], errors='coerce')

    df = df[df['Latency'] != 0]

    df["Host"] = df["IP"].map(host_map)

    df = df.sort_values(by=["IP", "Type"], ascending=[True, True])


    #df = df.groupby(["Host", "Type"], group_keys=False).apply(sample_entries)
    return df

def sample_entries(group):
    return group.sample(n=10)

def truncate_colormap(cmap_name, min_val=0, max_val=0.8, n_colors=256):
    cmap = cm.get_cmap(cmap_name, n_colors)
    new_cmap = mcolors.LinearSegmentedColormap.from_list(
        "truncated", cmap(np.linspace(min_val, max_val, n_colors))
    )
    return new_cmap

# Create a truncated Viridis colormap (removing the yellow)


def plot_results(df):
    unique_types = df["Type"].unique()

    hex_colors = {
        "SSH": "#5ec962",
        "Hop-H": "#21918c",
        "Hop-D":   "#3b528b",
    }


    plt.figure(figsize=(7.5, 3.75))
    ax = sns.barplot(data=df,
                     x="Host",
                     y="Latency",
                     hue="Type",
                     hue_order=["Hop-D", "Hop-H", "SSH"],
                     palette=hex_colors,
                     zorder=2,
                     width=0.8,
                     capsize=0.5,
                     errorbar=('ci', 95),
                     errwidth=1
                     )
    for container in ax.containers:
        ax.bar_label(container, fmt="%.2f", padding=3)
        ax.yaxis.grid(True, linestyle='--', alpha=0.7)

    #plt.title("Hop vs SSH - Time To Shell", fontsize=15)
    plt.ylabel("Time to Shell (s)", fontsize=12)
    plt.xlabel("", fontsize=0)
    plt.legend(fontsize=12)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.ylim(0, 2.85)

    entry_counts = df.groupby(["Host", "Type"]).size().unstack().fillna(0)
    print("\nNumber of Entries per Host and Protocol:")
    print(entry_counts)

    plt.tight_layout()

    # save the plot in pdf
    today = datetime.today().strftime("%Y-%m-%d")
    filename = f"tts_{today}.pdf"
    plt.savefig(filename)

    plt.show()



# Load data and plot results
df = load_data()
plot_results(df)
