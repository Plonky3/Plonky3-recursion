# Benchmarks

This section presents empirical performance results for the Plonky3 recursion system, including instructions for reproducibility across target machines.

**NOTE**: This library is still at an early stage, parameters have not been finely tuned yet, and as such performance results here may not reflect the full potential of the library.

## Setup

The reference examples are a Plonky3 uni-stark proof of the Keccak AIR imported directly, a Plonky3 batch-stark proof of the Fibonacci sequence generated with the `CircuitBuilder` of this library, and a 2-to-1 aggregation tree over basic `p3-batch-stark` proofs.

- Keccak example: set number of hashes with `-n` argument
```bash
RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3" RUST_LOG=info cargo run --release \
    --example recursive_keccak --features parallel -- -n 2500 
```

- Fibonacci example: set element index in the sequence with `-n` argument
```bash
RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3" RUST_LOG=info cargo run --release \
    --example recursive_fibonacci --features parallel -- -n 10000
```

- 2-to-1 aggregation example:
```bash
RUSTFLAGS="-Ctarget-cpu=native -Copt-level=3" RUST_LOG=info cargo run --release \
    --example recursive_aggregation --features parallel -- --field koala-bear
```

### Parameterization

Each example supports additional parameterization around the FRI parameters, namely:
- `--log-blowup`: logarithmic blowup factor for the LDE. Default 2.
- `--max-log-arity`: maximum arity allowed during the FRI folding phases. Default 2 (3 for the aggregation example, except with `--zk` or `--hash poseidon1`).
- `--log-final-poly-len`: logarithmic size (or degree) allowed for the final polynomial after folding. Default 5 (6 for the aggregation example).
- `--cap-height`: the height at which the MMCS tree is truncated for commitments. Default 0.
- `--commit-pow-bits`: additional PoW grinding during the FRI commit phase. Default 0.
- `--query-pow-bits`: additional PoW grinding during the FRI query phase. Default 15.
- `--num-recursive-layers`: number of recursive proofs to be generated in a chain, starting from the base proof (Keccak or Fibonacci). Default 3. For the aggregation example, this is the depth of the aggregation tree. Default 1.
- `--public-lanes`: number of public lanes for the table packing in recursive layers. Default 1.
- `--alu-lanes`: number of ALU lanes for the table packing in recursive layers. Default 3.
- `--horner-packed-steps`: number of consecutive Horner steps packed per ALU row. Default 4.
- `--recompose-lanes`: number of recompose lanes for the table packing in recursive layers. Default 1.
- `--security-level`: targeted conjectured security in bits. Default 124.
- `--zk`: activates the Zero-Knowledge property. Default `false`.

The aggregation example additionally accepts `--concurrent-pairs`, which proves all pairs of an aggregation level concurrently against one shared preparation. It shortens the whole tree, but each individual proof then shares the cores, so its reported per-layer time grows; the results below are measured without it.

The examples run on the [mimalloc](https://github.com/microsoft/mimalloc) allocator and keep freed memory mapped between recursion layers.

## Results

Running on a Apple M4 pro, 14 Cores, with **KoalaBear** field and extension of **degree 4**, using default parameters mentioned above at a 124-bit security target, performance benchmarks are as follows:

*NOTE*: In production systems, circuits may be pre-generated offline and cached to reduce overhead in fixed recursive layers.

- **Keccak AIR program:** (1,000 hashes)
  - Base uni-stark proof: 720 ms
  - 1st recursion layer: 663 ms
  - 2nd and 3rd recursion layers: 147 ms
  - 4th and next recursion layers: 109 ms

- **Fibonacci multi-AIR program:** (10,000th element)
  - Base batch-stark proof: 42.6 ms
  - 1st and 2nd recursion layers: 147 ms
  - 3rd and next recursion layers: 109 ms

- **2-to-1 aggregation:**
  - Base batch-stark proof: 14.1 ms
  - 1st aggregation layer: 121 ms
  - 2nd and next aggregation layers: 193 ms
