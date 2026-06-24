# p3-poseidon1-circuit-air

An AIR for the Poseidon1 permutation table used in recursion, handling sponge
hashing and compression. Built on the shared layout from
`p3-poseidon-circuit-cols`.

Key items:

- `Poseidon1Params` — the backend parameter trait
- `BabyBearD1Width16`, `BabyBearD4Width16/24`, `KoalaBearD1Width16`, … — concrete parameterizations, each with `round_constants` and `default_air*` constructors
- columns and public types for the table, wrapping `PoseidonCircuitCols`

Part of [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion), dual-licensed under MIT and Apache 2.0.
