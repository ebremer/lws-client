// SPDX-License-Identifier: MIT
//! The HTTP transport: `reqwest` everywhere but WASI, where the host's `wasi:http` sends the
//! requests (the `wasm32-wasip2` target, built into a WebAssembly component).
//!
//! Both offer the same small API, the part of `reqwest`'s that the client uses (`request`, `get`
//! and `post`, `header(s)`, `timeout`, `body`, `send`; `status`, `url`, `headers`, `bytes` and
//! `chunk`), so that the rest of the crate is one code path on every target. Neither follows
//! redirects: the client follows them itself, one hop at a time, and the token exchange never
//! does.

#[cfg(not(target_os = "wasi"))]
mod native;
#[cfg(target_os = "wasi")]
mod wasi;

#[cfg(not(target_os = "wasi"))]
pub(crate) use native::{Body, HttpClient, Response, body, client};
#[cfg(target_os = "wasi")]
pub(crate) use wasi::{Body, HttpClient, Response, body, client};
