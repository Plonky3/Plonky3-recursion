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
- `--max-log-arity`: maximum arity allowed during the FRI folding phases. Default 3.
- `--log-final-poly-len`: logarithmic size (or degree) allowed for the final polynomial after folding. Default 5.
- `--cap-height`: the height at which the MMCS tree is truncated for commitments. Default varies per examples.
- `--commit-pow-bits`: additional PoW grinding during the FRI commit phase. Default 0.
- `--query-pow-bits`: additional PoW grinding during the FRI query phase. Default 16.
- `--num-recursive-layers`: number of recursive proofs to be generated in a chain, starting from the base proof (Keccak or Fibonacci). Default 3.
- `--witness-lanes`: number of witness lanes for the table packing in recursive layers. Default varies per examples.
- `--public-lanes`: number of public lanes for the table packing in recursive layers. Default 2.
- `--alu-lanes`: number of ALU lanes for the table packing in recursive layers. Default 3.
- `--security-level`: targeted conjectured security in bits. Default 124.
- `--zk`: activates the Zero-Knowledge property. Default `false`.

## Results

Running on a Apple M4 pro, 14 Cores, with **KoalaBear** field and extension of **degree 4**, using default parameters mentioned above at a 124-bit security target, performance benchmarks are as follows:

*NOTE*: In production systems, circuits may be pre-generated offline and cached to reduce overhead in fixed recursive layers.

- **Keccak AIR program:** (1,000 hashes)
  - Base uni-stark proof: 1.37 s
  - 1st recursion layer: 1.03 s
  - 2nd and 3rd recursion layers: 230 ms
  - 4th and next recursion layers: 179 ms

- **Fibonacci multi-AIR program:** (10,000th element)
  - Base batch-stark proof: 82.6 ms
  - 1st recursion layer: 171 ms
  - 2nd and 3rd recursion layers: 230 ms
  - 4th and next recursion layers: 178 ms

- **2-to-1 aggregation:**
  - Base batch-stark proof: 28 ms
  - 1st aggregation layer: 166 ms
  - 2nd and next aggregation layers: 280 ms
