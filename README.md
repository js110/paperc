# Report verification experiments

This repository contains a Go research prototype, automated tests, benchmark scripts, and recorded results for a report-verification experiment. All event values and reports in the experiments are synthetic; the recorded timings are local software measurements.

## Requirements

- Go 1.26.8 (the `go` command can download the matching toolchain automatically).
- The module versions in `prototype/go.mod` and `prototype/go.sum`.
- Python 3 and Matplotlib to render the optional benchmark plot.

## Run tests

```sh
cd prototype
go test -count=1 -timeout=15m ./...
```

The candidate context-hiding circuit is a separate experimental base-circuit variant. It has functional tests, but has not been established as a complete collusion-resistant system. The context-linkability test demonstrates a shared-context join in a synthetic example.

## Run benchmarks

From `prototype/`, each command records a single setup and one warm-up followed by 30 measurements:

```sh
EVENT_BENCH_RUNS=30 go test -run '^TestBenchmarkExperiment$' -count=1 -timeout=30m -v
EVENT_REGION_BENCH_RUNS=30 go test -run '^TestRegionBenchmarkExperiment$' -count=1 -timeout=30m -v
EVENT_ACCOUNTABILITY_BENCH_RUNS=30 go test -run '^TestAccountabilityBenchmarkExperiment$' -count=1 -timeout=30m -v
EVENT_REVOCATION_BENCH_RUNS=30 go test -run '^TestRevocationBenchmarkExperiment$' -count=1 -timeout=30m -v
EVENT_END_TO_END_RUNS=30 go test -run '^TestEndToEndExperiment$' -count=1 -timeout=30m -v
EVENT_BINDING_COST=1 go test -run '^TestBindingCostExperiment$' -count=1 -timeout=30m -v
```

To reproduce the region-depth experiments, run `python3 experiments/run_region_scaling.py` from the repository root. It creates temporary source copies for each depth. `python3 experiments/plot_results.py` renders the four recorded proof-operation benchmarks into `experiments/benchmark.pdf`.

The `experiments/` directory includes the original logs. The local in-process workflow does not measure network communication, physical sensing, or a multi-gateway deployment. Local Groth16 setup is for research and is not a production setup ceremony. Recorded results depend on hardware, toolchain, and runtime conditions.
