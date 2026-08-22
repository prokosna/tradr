# ADR-0013: Layer 1 async traits return boxed futures

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

`tradr-core` declares the `Transport` and `Vfs` traits and **depends on nothing** — not on `tokio`, not on `futures`, not on `async-trait`. Invariant I4 is enforced mechanically: `ci/layer-deps.sh` fails if `crates/tradr-core/Cargo.toml` declares a dependency at all.

Both traits describe operations that are unavoidably asynchronous. So the core has to express "returns a future" using nothing but the standard library, and the shape it picks constrains every Layer 1 trait written afterwards.

Two candidate shapes exist, and the choice between them is not a matter of taste.

**`async fn` in a trait** is the idiomatic form, stable since Rust 1.75:

```rust
trait Transport {
    async fn connect(&self, candidate: &Candidate) -> Result<Connection, TransportError>;
}
```

It is not usable here, and the reason is structural rather than stylistic. [docs/03](../03-discovery-and-transport.md#path-selection) does not select a transport; it **races every candidate at once and adopts the winner**. That requires holding transports of different concrete types in one collection, which requires `dyn Transport`, and an `async fn` in a trait is not dyn compatible:

```
error[E0038]: the trait `Transport` is not dyn compatible
 --> src/lib.rs:6:18
  |
3 |     async fn connect(&self, addr: &str) -> Result<(), ()>;
  |              ^^^^^^^ ...because method `connect` is `async`
```

Measured on the toolchain this project pins, rustc 1.98.0, rather than taken from documentation.

An `async fn` in a trait also provides no way to require that the returned future is `Send`, which a multi-threaded Tokio runtime needs. The usual answers to both problems — `async-trait`, `trait_variant` — are dependencies, and the core may not have one.

## Decision

**Async Layer 1 trait methods return an explicitly boxed future, and the alias for it is declared in `tradr-core`.**

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Transport: Send + Sync {
    fn connect<'a>(&'a self, candidate: &'a Candidate)
        -> BoxFuture<'a, Result<Connection, TransportError>>;
}
```

This is what `async-trait` expands to. Writing the expansion by hand costs a few characters per method and removes the dependency that produces it.

- The `Send` bound on the future is **required, not decorative**. Removing it and asking the compiler to prove a composed future `Send` fails with `future cannot be sent between threads safely`, which was verified before the bound was written down
- The trait itself is `Send + Sync`, so a registry of transports can be shared across tasks
- The `'a` lifetime lets an implementation borrow `&self` across an await, which is the case every real implementation needs

## Reasoning

1. **It is the only shape that supports racing.** Phase 3 of path selection is the design's core mechanism, and it cannot be written against a trait that has no vtable.

2. **The cost is one allocation per call, at connection granularity.** `connect` runs once per candidate per attempt. Even on the data path the unit is a 1 MiB chunk ([invariant I6](../../CLAUDE.md#8-invariants-that-must-not-break)), so a boxed future per chunk is one allocation per megabyte. This is not a hot path in any measurable sense, and if that ever stops being true the fix is confined to the trait and its implementations.

3. **It keeps `tradr-core` at zero dependencies.** The alternative is adding `async-trait` to the one crate whose emptiness is a checked invariant, and weakening `layer-deps.sh` to permit it. A check with an exception is a check people learn to argue with.

## Consequences

- **`Vfs`, `Transport`, and any later Layer 1 trait with asynchronous methods use `BoxFuture`.** Consistency here is worth more than saving an allocation in the one case that might not need it.
- **`KeyStore` stays synchronous**, as [ADR-0011](0011-keystore-exposes-operations.md) declared it. That is a live question rather than a settled one: an Android Keystore `sign` is an IPC to `keystore2` and blocks for milliseconds, and Noise's static-key agreement runs once per connection. Blocking a runtime worker there is tolerable and not free. Revisiting it belongs with the Noise work in M1, not here, and it is recorded as deferred rather than answered.
- **Implementations write `Box::pin(async move { ... })`.** That is mechanical, and it is the whole of the ergonomic cost.
- **Tests in `tradr-core` need no runtime.** A test implementation returns `Box::pin(async { ... })` with a value already available, and the future completes on the first poll.
