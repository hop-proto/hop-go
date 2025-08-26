import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import matplotlib.colors as mcolors
from datetime import datetime

data = pd.read_csv('keystrokes_data.csv')

styles = {
    'local': ('Local', '3-'),
    'empty': ('    ', '4-'),
    'hop_usa': ('Hop USA', '1-'),
    'ssh_usa': ('SSH USA', '1:'),
    'hop_europe': ('Hop Europe', '0-'),
    'ssh_europe': ('SSH Europe', '0:'),
    'hop_asia': ('Hop Asia', '2-'),
    'ssh_asia': ('SSH Asia', '2:'),
}

hex_colors2 = {
    0: "#E58606",
    1: "#5D69B1",
    2: "#52BCA3",
    3: "#99C945",
    4: "#CC61B0",
    5: "#24796C",
    6: "#DAA51B",
    7: "#2F8AC4",
}

hex_colors = {
    0: "#5ec962",
    1: "#21918c",
    2: "#3b528b",
    3: "#E58606",
    4: "#FFFFFF",
}

def truncate_colormap(cmap_name='viridis', min_val=0.0, max_val=0.75, n_colors=256):
    base_cmap = cm.get_cmap(cmap_name, n_colors)
    new_colors = base_cmap(np.linspace(min_val, max_val, n_colors))
    new_cmap = mcolors.LinearSegmentedColormap.from_list('truncated', new_colors)
    return new_cmap

cmap = truncate_colormap('viridis', 0.0, 0.65, len(styles))
colors = [cmap(i / len(styles)) for i in range(len(styles))]

plt.figure(figsize=(5.89, 3))
for color, (column, (label, style)) in zip(colors, styles.items()):
    color_index = int(style[0])
    linestyle = style[1:] if len(style) > 1 else '-'

    np.sort(data)
    sorted_data = np.sort(data[column])
    y = 1. * np.arange(len(sorted_data)) / (len(sorted_data) - 1)
    plt.plot(sorted_data, y, color=hex_colors[color_index], linestyle=linestyle, label=label, linewidth=3)

plt.xlabel("Keystroke display time (ms)")
plt.ylabel("CDF")
plt.xlim(0, 250)

plt.legend(loc='lower center', bbox_to_anchor=(0.5, 1.02), ncol=4, frameon=True)
plt.grid(True)
plt.tight_layout(rect=[0, 0, 1, 0.95])

today = datetime.today().strftime("%Y-%m-%d")
filename = f"keystrokes_{today}.pdf"
plt.savefig(filename)
plt.show()
