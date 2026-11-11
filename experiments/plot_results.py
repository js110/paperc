#!/usr/bin/env python3
"""Render figures from the recorded local prototype experiment."""
from pathlib import Path
import csv
import io
import statistics
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

root = Path(__file__).resolve().parent.parent
def read_samples(name):
    lines = (root / 'experiments' / name).read_text().splitlines()
    header = lines.index('sample,prove_ns,verify_ns,proof_bytes,public_witness_bytes')
    rows = []
    for line in lines[header+1:]:
        fields = line.split(',')
        if len(fields) == 5 and fields[0].isdigit():
            rows.append([int(x) for x in fields])
    if len(rows) != 30:
        raise ValueError(f'expected 30 measured samples in {name}, got {len(rows)}')
    return rows
base=read_samples('benchmark.log')
region=read_samples('region_benchmark.log')
accountability=read_samples('accountability_benchmark.log')
active=read_samples('revocation_benchmark.log')
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'pdf.fonttype':42})
fig, axes = plt.subplots(1,2,figsize=(7.1,2.8))
for ax, col, title in ((axes[0],1,'Proof generation'), (axes[1],2,'Proof verification')):
    for rows, label, color, marker in ((base,'Rectangle','#1f5d87','o'),(region,'Region','#b35920','x'),(accountability,'Accountability','#427849','^'),(active,'Active credential','#80548b','+')):
        values = [r[col]/1e6 for r in rows]
        ax.scatter(range(1,len(values)+1),values,s=15,color=color,alpha=.76,marker=marker,label=label)
        ax.axhline(statistics.median(values),color=color,linestyle='--',linewidth=.85)
    ax.set(title=title,xlabel='Measured run',ylabel='Time (ms)',xlim=(0,31))
    ax.grid(axis='y',color='0.88',linewidth=.6)
handles, labels = axes[0].get_legend_handles_labels()
fig.legend(handles, labels, frameon=False, loc='lower center', ncol=4, fontsize=8)
fig.tight_layout(rect=(0, .11, 1, 1))
fig.savefig(root/'experiments'/'benchmark.pdf',bbox_inches='tight')

