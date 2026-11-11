#!/usr/bin/env python3
"""Rebuild fixed-depth region circuits in temporary copies and retain raw logs."""
from pathlib import Path
import os, shutil, subprocess, tempfile
root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='event-region-scale-') as temp:
    for depth in (4, 6, 8):
        dest = Path(temp) / str(depth)
        shutil.copytree(root / 'prototype', dest)
        p = dest / 'region.go'
        text = p.read_text()
        assert 'RegionDepth      = 8' in text
        p.write_text(text.replace('RegionDepth      = 8', f'RegionDepth      = {depth}'))
        p = dest / 'region_benchmark_test.go'
        text = p.read_text().replace('region_depth=8 region_cells=256', f'region_depth={depth} region_cells={1 << depth}').replace('x == 20 && y == 30', 'x == 10 && y == 20').replace('[3]uint32{20, 30, 150}', '[3]uint32{10, 20, 150}')
        p.write_text(text)
        env = dict(os.environ, EVENT_REGION_BENCH_RUNS='30')
        with (root / 'experiments' / f'region_scale_{depth}.log').open('w') as log:
            subprocess.run(['go', 'test', '-run', '^TestRegionBenchmarkExperiment$', '-count=1', '-timeout=15m', '-v'], cwd=dest, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        print('completed depth', depth, flush=True)
