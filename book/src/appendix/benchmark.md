# Benchmarks

This section presents empirical performance results for the Plonky3 recursion system, including instructions for reproducibility across target machines.

**NOTE**: This library is still at an early stage, parameters have not been finely tuned yet, and as such performance results here may not reflect the full potential of the library.

## Setup

The reference examples are a Plonky3 uni-stark proof of the Keccak AIR imported directly, a Plonky3 batch-stark proof of the Fibonacci sequence generated with the `CircuitBuilder` of this library, and a 2-to-1 aggregation tree over basic `p3-batch-stark` proofs.

- Keccak example: set number of hashes with `-n` argument
```bash
RUSTFLAGS=-Ctarget-cpu=native RUSTFLAGS=-Copt-level=3 RUST_LOG=info cargo run --release \
    --example recursive_keccak --features parallel -- -n 2500 
```

- Fibonacci example: set element index in the sequence with `-n` argument
```bash
RUSTFLAGS=-Ctarget-cpu=native RUSTFLAGS=-Copt-level=3 RUST_LOG=info cargo run --release \
    --example recursive_fibonacci --features parallel -- -n 10000
```

- 2-to-1 aggregation example:
```bash
RUSTFLAGS=-Ctarget-cpu=native RUSTFLAGS=-Copt-level=3 RUST_LOG=info cargo run --release \
    --example recursive_aggregation --features parallel -- --field koala-bear
```

### Parameterization

Each example supports additional parameterization around the FRI parameters, namely:
- `--log-blowup`: logarithmic blowup factor for the LDE. Default 3.
- `--max-log-arity`: maximum arity allowed during the FRI folding phases. Default 4.
- `--log-final-poly-len`: logarithmic size (or degree) allowed for the final polynomial after folding. Default 5.
- `--cap-height`: the height at which the MMCS tree is truncated for commitments. Default 0 (unique root).
- `--commit-pow-bits`: additional PoW grinding during the FRI commit phase. Default 0.
- `--query-pow-bits`: additional PoW grinding during the FRI query phase. Default 16.
- `--num-recursive-layers`: number of recursive proofs to be generated in a chain, starting from the base proof (Keccak or Fibonacci). Default 3.

## Results

Running on a Apple M4 pro, 14 Cores, with **KoalaBear** field and extension of **degree 4**, using default parameters mentioned above, performance benchmarks are as follows:

- **Keccak AIR program:** (1,000 hashes)
  - Base uni-stark proof: 1.40 s
  - 1st recursion layer: 1.54 s
  - 2nd recursion layer: 358 ms
  - 3rd recursion layer: 356 ms


- **Fibonacci multi-AIR program:** (10,000th element)
  - Base batch-stark proof: 84.7 ms
  - 1st recursion layer: 226 ms
  - 2nd recursion layer: 388 ms
  - 3rd recursion layer: 357 ms

- **2-to-1 aggregation:**
  - Base batch-stark proof: 30 ms
  - 1st aggregation layer: 358 ms
  - 2nd aggregation layer: 580 ms
  - 3rd and next aggregation layers: 576 ms
