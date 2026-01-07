import pandas as pd
from datetime import datetime
import seaborn as sns
import matplotlib.pyplot as plt


df = pd.read_csv("transfer_data_local.csv")

df["File Size"] = df["File Size"].replace({
    "10MB_file": "10MB",
    "100MB_file": "100MB",
    "1GB_file": "1GB"
})

df["Protocol"] = df["Protocol"].replace({
    "rsync_ssh_reno": "SSH NewReno",
    "rsync_ssh_cubic": "SSH CUBIC",
    "rsync_hop": "Hop",
})

df["File Size"] = pd.Categorical(
    df["File Size"],
    categories=["10MB", "100MB", "1GB"],
    ordered=True
)

hex_colors = {
    "Hop": "#3b528b",
    "SSH NewReno": "#5ec962",
    "SSH CUBIC": "#21918c"
}

g = sns.catplot(
    data=df,
    x="File Size",
    y="Speed (MB/s)",
    hue="Protocol",
    col="Host",
    kind="box",
    order=["10MB", "100MB", "1GB"],
    hue_order=["SSH NewReno", "Hop", "SSH CUBIC"],
    palette=hex_colors,
    height=4,
    aspect=0.5,
)

for ax in g.axes.flat:
    ax.grid(True, which="major", axis="y", linestyle="--", alpha=0.7)


for ax in g.axes.flat:
    ax.set_ylim(0, 25)


g._legend.remove()

handles, labels = g.axes.flat[-1].get_legend_handles_labels()

g.axes.flat[-1].legend(
    handles,
    labels,
    loc="upper center",
    ncol=1,
    frameon=True,
    fancybox=True,
    shadow=False,
    bbox_to_anchor=(0.68, 0.87)
)


g.set_titles("{col_name}", y=0.9)
g.set_axis_labels("File Size", "Speed (MB/s)")


plt.tight_layout()

today = datetime.today().strftime("%Y-%m-%d")
filename = f"file_transfer_{today}.pdf"
plt.savefig(filename)

plt.show()

