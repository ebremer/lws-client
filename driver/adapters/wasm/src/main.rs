// SPDX-License-Identifier: MIT
//! The WebAssembly adapter of the lws-client driver: runs the operations of driver/PROTOCOL.md
//! (`lws-driver/1`) with the lws-client component of ../../../wasm, in Wasmtime.
//!
//! ```text
//! lws-driver-adapter-wasm [COMPONENT]
//! ```
//!
//! COMPONENT is the component file, by default `lws_client.wasm` next to the executable. The
//! adapter calls the component through its interface (wit/lws.wit), as any host of the
//! component would: it tests the component, not the Rust crate inside it.
//!
//! The driver writes one JSON request per line to stdin; the adapter answers each with one JSON
//! line on stdout. stdout carries protocol messages only: everything else goes to stderr.

mod args;
mod errors;
mod ops;
mod results;
mod runtime;

use std::io::{BufRead, Write};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::errors::Failure;
use crate::ops::{OPERATIONS, State};
use crate::runtime::Runtime;

/// The bindings of the component's world (../../../wasm/wit/lws.wit).
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../../wasm/wit",
        world: "lws-client",
    });
}

/// The component's types, in one place.
pub(crate) mod lws {
    pub(crate) use crate::bindings::ebremer::lws::types::{
        Created, Error, ErrorKind, Item, Link, Metadata, Page, PatchOp, PatchOperation, QueryGroup,
        RelationFilter, StorageDescription, Subscription, SubscriptionRequest, TypeIndexPage,
        TypeQuery, Updated,
    };
    pub(crate) use crate::bindings::exports::ebremer::lws::client::{
        Auth, BearerToken, CreateOptions, DeleteOptions, KeyAlgorithm, Options, ReadOptions,
        SelfSignedKey, SubjectToken, UpdateOptions,
    };
}

/// The arguments of a request.
pub(crate) type Args = Map<String, Value>;

/// Writes one protocol message as a line on stdout, and flushes it.
fn write(message: &Value) {
    let line = message.to_string();
    let mut out = std::io::stdout().lock();
    if let Err(e) = writeln!(out, "{line}").and_then(|()| out.flush()) {
        // Nobody is reading the answers any more: the driver is gone.
        eprintln!("lws-driver-adapter-wasm: cannot write to stdout: {e}");
        std::process::exit(1);
    }
}

fn failure(id: Value, error: &Failure) -> Value {
    json!({"id": id, "ok": false, "error": errors::error_result(error)})
}

/// Answers one request line; returns `false` once the adapter should exit.
fn handle(state: &mut State, line: &str) -> bool {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            write(&failure(
                Value::Null,
                &Failure::invalid("the request is not JSON"),
            ));
            return true;
        }
    };
    let Value::Object(request) = request else {
        write(&failure(
            Value::Null,
            &Failure::invalid("the request is not a JSON object"),
        ));
        return true;
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let op = request.get("op").and_then(Value::as_str);
    let Some(op) = op.filter(|op| OPERATIONS.contains(op)) else {
        let name = match request.get("op") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => "undefined".to_owned(),
        };
        write(&failure(
            id,
            &Failure::unsupported(format!("unknown operation '{name}'")),
        ));
        return true;
    };
    let empty = Args::new();
    let args = match request.get("args") {
        None | Some(Value::Null) => Ok(&empty),
        Some(Value::Object(args)) => Ok(args),
        Some(_) => Err(Failure::invalid("args must be an object")),
    };
    let outcome = match args {
        Ok(args) => std::panic::catch_unwind(AssertUnwindSafe(|| state.run(op, args)))
            .unwrap_or_else(|panic| {
                // The store may be in any state after a panic in the middle of a call.
                state.restart();
                Err(Failure::panic(panic.as_ref()))
            }),
        Err(e) => Err(e),
    };
    match outcome {
        Ok(result) => write(&json!({"id": id, "ok": true, "result": result})),
        Err(e) => write(&failure(id, &e)),
    }
    op != "shutdown"
}

/// The component file: the argument, or `lws_client.wasm` next to the executable.
fn component_path() -> PathBuf {
    if let Some(path) = std::env::args_os().nth(1) {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().unwrap_or_default();
    exe.with_file_name("lws_client.wasm")
}

fn main() {
    let path = component_path();
    let state = Runtime::load(&path).and_then(State::new);
    let mut state = match state {
        Ok(state) => state,
        Err(e) => {
            eprintln!(
                "lws-driver-adapter-wasm: cannot load the component {}: {e:?}",
                path.display()
            );
            std::process::exit(1);
        }
    };
    write(&json!({"hello": {
        "protocol": "lws-driver/1",
        "language": "wasm",
        "library": state.library(),
        "operations": OPERATIONS,
    }}));
    let mut input = std::io::stdin().lock();
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match input.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buffer);
                if line.trim().is_empty() {
                    continue;
                }
                if !handle(&mut state, &line) {
                    break;
                }
            }
            Err(e) => {
                eprintln!("lws-driver-adapter-wasm: cannot read stdin: {e}");
                break;
            }
        }
    }
}
