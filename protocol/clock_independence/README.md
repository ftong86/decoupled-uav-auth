# Clock-Independence Statistical Experiment

This experiment is derived from the verified `prototype_validation_v2.cpp`.
It keeps the M0 -> M1 -> M2 -> M3 -> commit protocol flow and changes the
experiment driver to collect statistical ASR/FRR results.

## Build (WSL/Linux)

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

## Run

Default:
```bash
./clock_experiment
```

Defaults:
- windows: 100, 500, 1000 ms
- trials per condition: 1000
- one-way delay: Uniform[10, 50] ms
- fixed seed: 20260929

Explicit:
```bash
./clock_experiment 100 500 1000 1000 10 50 20260929
```

Arguments:
`W1 W2 W3 trials delay_min_ms delay_max_ms seed`

Outputs:
- `clock_independence_summary.csv`
- `clock_independence_metadata.txt`

Timestamp baseline:
`abs(clock_offset_ms + one_way_delay_ms) <= window_ms`

The same generated delay trace is used for Epoch and Timestamp for each
(window, offset-ratio) condition.

IMPORTANT: 100/500/1000 ms are experiment values only. Before publication,
justify the timestamp windows using the selected baseline protocol(s), or
replace them with the baseline's specified acceptance windows.
