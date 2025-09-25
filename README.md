# Plonky3-recursion
Plonky3 native support for uni-stark recursion.

## Modular circuit builder & runtime policy

The `CircuitBuilder<F>` uses a runtime policy to control which non-primitive operations (Merkle, FRI, etc.) are allowed. Primitive ops like `Const`, `Public`, `Add` are always available.

By default, all non-primitive ops are disabled with `DefaultProfile`.
Define a custom policy to enable them, or use `AllowAllProfile` to activate them all.

Trying to access an op not supported by the selected policy in the circuit builder will result in a runtime error.
