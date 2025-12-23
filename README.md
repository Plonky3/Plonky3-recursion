# Plonky3-recursion
Plonky3 native support for uni-stark recursion.

## Production Use

This codebase is under active development and hasn't been audited yet. As such, we do not recommend its use in any
production software.

[![Coverage](https://github.com/Plonky3/Plonky3-recursion/actions/workflows/coverage.yml/badge.svg)](https://plonky3.github.io/Plonky3-recursion/coverage/) (_updated weekly_)

## Documentation

Documentation is still incomplete and will be improved over time.
You can go through the [Plonky3 recursion book](https://Plonky3.github.io/Plonky3-recursion/)
for a walkthrough of the recursion approach.

## Modular circuit builder & runtime policy

The `CircuitBuilder<F>` uses a runtime policy to control which non-primitive operations (MMCS, FRI, etc.) are allowed. Primitive ops like `Const`, `Public`, `Add` are always available.

By default, all non-primitive ops are disabled with `DefaultProfile`.
Define a custom policy to enable them, or use `AllowAllProfile` to activate them all.

Trying to access an op not supported by the selected policy in the circuit builder will result in a runtime error.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
