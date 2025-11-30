# Comprehensive Benchmark & Stress-Test Suite

## Overview

This directory contains two Python scripts for comprehensive performance testing of sushCore:

1. **`run_benchmarks.py`**: Executes heavy stress tests and collects raw performance data
2. **`analyze_results.py`**: Visualizes the collected data for publication

## Script 1: `run_benchmarks.py`

### Purpose
Performs 3 comprehensive experiments using real sushCore implementations (no mocks):

### Experiment A: Crypto Overhead Analysis (CPU Bound)
- **Goal**: Measure the exact time cost of the Quantum-Safe layer
- **Method**:
  - Initializes `QuantumObfuscator` with real ML-KEM handshake
  - Generates random payloads of sizes: [1KB, 10KB, 100KB, 1MB]
  - Measures wall-clock time for `obfuscate_data()` vs `deobfuscate_data()`
  - Repeats 50 times for statistical significance
- **Output Metrics**:
  - Average obfuscation time (ms)
  - Average deobfuscation time (ms)
  - Total processing time (ms)
  - Standard deviation
  - Throughput (Mbps)

### Experiment B: End-to-End Throughput (IO Bound)
- **Goal**: Measure effective bandwidth with all security layers active
- **Method**:
  - Starts a local `SushServer` on port 9001 (background task)
  - Starts a `SushClient` connected to it
  - Transfers a 10MB virtual file through the client
  - Compares two modes:
    1. `TransportMode.DIRECT` (No steganography/morphing)
    2. `TransportMode.STEGANOGRAPHIC` (With morphing overhead)
  - Simulates network delay using `asyncio.sleep(random.uniform(0.01, 0.05))`
- **Output Metrics**:
  - Bytes sent/received
  - Elapsed time (seconds)
  - Effective throughput (Mbps)
  - Mode comparison

### Experiment C: Adaptive Control Response Time
- **Goal**: Measure how fast the AI reacts to threats
- **Method**:
  - Feeds a stream of `NetworkMetrics` into `AdaptiveControlLoop`
  - Starts with "Normal" metrics (low loss, low latency)
  - At T=5s, injects "Attack" metrics (high packet loss, connection resets)
  - Measures the time difference (delta) between attack injection and `system_state` changing to `ADAPTING`
- **Output Metrics**:
  - Initial system state
  - Final system state
  - Reaction time (ms)
  - Number of attack metrics injected

### Data Persistence
All results are saved to: `tests/data/benchmark_results.csv`

### Usage
```bash
python tests/run_benchmarks.py
```

---

## Script 2: `analyze_results.py`

### Purpose
Reads `tests/data/benchmark_results.csv` and generates publication-ready visualizations.

### Generated Plots

#### 1. `crypto_overhead.png` / `crypto_overhead.pdf`
- **Type**: Bar chart
- **Content**: Encryption time per MB for different payload sizes
- **Shows**: How crypto overhead scales with payload size
- **Location**: `tests/data/plots/crypto_overhead.png`

#### 2. `throughput_comparison.png` / `throughput_comparison.pdf`
- **Type**: Bar chart
- **Content**: Comparison of Direct vs. Steganographic throughput
- **Shows**: Performance impact of steganographic mode
- **Location**: `tests/data/plots/throughput_comparison.png`

#### 3. `reaction_time.png` / `reaction_time.pdf`
- **Type**: Timeline
- **Content**: Attack event vs. adaptation event timeline
- **Shows**: Response latency of adaptive control loop
- **Location**: `tests/data/plots/reaction_time.png`

### Summary Statistics
The script also prints summary statistics to console:
- Experiment A: Average processing times and throughput per payload size
- Experiment B: Throughput comparison between modes
- Experiment C: Mean reaction time and standard deviation

### Usage
```bash
python tests/analyze_results.py
```

---

## Requirements

All dependencies are listed in `requirements.txt`. Key libraries:
- `numpy` - Statistical calculations
- `pandas` - Data manipulation
- `matplotlib` - Visualization
- All sushCore modules (imported from `sush.*`)

## Output Structure

```
tests/
├── data/
│   ├── benchmark_results.csv      # Raw benchmark data
│   └── plots/
│       ├── crypto_overhead.png
│       ├── crypto_overhead.pdf
│       ├── throughput_comparison.png
│       ├── throughput_comparison.pdf
│       ├── reaction_time.png
│       └── reaction_time.pdf
├── run_benchmarks.py
└── analyze_results.py
```

## Notes

- **Real Implementations Only**: No mocks or simulations. All tests use actual sushCore classes.
- **Localhost Simulation**: Network delay is simulated using `asyncio.sleep()` for the network transmission part, but CPU processing (crypto, logic) uses real wall-clock time.
- **Statistical Significance**: Experiment A repeats 50 times per payload size for reliable averages.
- **Error Handling**: Scripts gracefully handle errors and log them without crashing.

## Integration with Research Paper

These benchmarks provide:
1. **Performance Metrics**: Real-world crypto overhead measurements
2. **Throughput Analysis**: End-to-end bandwidth with security layers
3. **Adaptive Response Data**: AI reaction time to threats

All plots are publication-ready (PNG + PDF formats, 300 DPI resolution).

