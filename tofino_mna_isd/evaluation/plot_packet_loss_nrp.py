import matplotlib.pyplot as plt
import numpy as np

# Data for the bar diagram
groups = ['No link overload', 'Link overload w/o\nnetwork slicing', 'Link overload w/\nnetwork slicing']
bar_labels = ['NRP X', 'NRP Y', 'NRP Z', "Interference traffic"]
data = [
    [0.5, 0.5, 0.5, 0],  # Group 1 data
    [58.75, 59.0, 40.3, 50.27],  # Group 2 data
    [0.5, 0.5, 0.5, 100],  # Group 3 data
]
colors = ['#990000', '#3399FF', '#00994D', '#666666']  # Colors for bars

# Bar width and x locations
bar_width = 0.15
x = np.arange(len(groups))

# Plot each bar in the groups
#fig, ax = plt.subplots(figsize=(8, 6))
fig = plt.figure(figsize=(2880/100, 1620/100))
ax = fig.add_subplot()
for i in range(len(bar_labels)):
    ax.bar(x + i * bar_width, [d[i] for d in data], bar_width, label=bar_labels[i], color=colors[i])


#ax.set_xlabel('Throughput (Gb/s)', fontsize=60)
ax.set_ylabel('Packet loss (%)', fontsize=60)
ax.tick_params(axis="x", labelsize=50, width=5, length=14)
ax.tick_params(axis="y", labelsize=50, width=5, length=14)

# Customize the x-axis
tick_positions = x + bar_width
ax.set_xticks(tick_positions)
ax.set_xticklabels(groups)

# Add labels, legend, and title
#ax.set_xlabel('Groups')
ax.legend(fontsize=50)

# Show the plot
plt.tight_layout()
plt.savefig('nrp.pdf')    