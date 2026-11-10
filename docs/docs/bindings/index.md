---
title: Bindings
sidebar_position: 1
---

# Bindings

httpcloak ships in six languages. Go is the native implementation. Python, Node.js, .NET, Kotlin on Android and Rust each call into the same cgo-built library, so the wire behaviour matches across all six surfaces.

## In this section

- [Go](./go): the native API, idiomatic Go
- [Python](./python): a `requests`-shaped wrapper over cgo
- [Node.js](./nodejs): koffi-backed, ESM and CJS both work
- [.NET](./dotnet): P/Invoke wrapper for .NET 8+
- [Android (Kotlin)](./android): coroutine-first Kotlin API over a thin JNI bridge
- [Rust](./rust): a safe, statically linked API, blocking or async on any executor
