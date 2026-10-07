// SPDX-License-Identifier: MIT
//! The Rust adapter of the lws-client driver: runs the operations of driver/PROTOCOL.md
//! (`lws-driver/1`) with the lws-client of ../../../rust.
//!
//! The driver writes one JSON request per line to stdin; the adapter answers each with one JSON
//! line on stdout. stdout carries protocol messages only: everything else goes to stderr.

mod args;
mod errors;
mod ops;
mod results;

use std::io::{BufRead, Write};
use std::panic::AssertUnwindSafe;

use futures_util::FutureExt as _;
use serde_json::{Map, Value, json};

use crate::errors::Failure;
use crate::ops::{OPERATIONS, State};

/// The library and its version, as announced in the hello and returned by `configure`.
pub(crate) const LIBRARY: &str = lws_client::constants::USER_AGENT;

/// The arguments of a request.
pub(crate) type Args = Map<String, Value>;

/// Writes one protocol message as a line on stdout, and flushes it.
fn write(message: &Value) {
    let line = message.to_string();
    let mut out = std::io::stdout().lock();
    if let Err(e) = writeln!(out, "{line}").and_then(|()| out.flush()) {
        // Nobody is reading the answers any more: the driver is gone.
        eprintln!("lws-driver-adapter-rust: cannot write to stdout: {e}");
        std::process::exit(1);
    }
}

fn failure(id: Value, error: &Failure) -> Value {
    json!({"id": id, "ok": false, "error": errors::error_result(error)})
}

/// Reads stdin on a thread of its own, so that the runtime keeps running (and the HTTP
/// connections it holds stay serviced) while the adapter waits for the next request.
fn read_lines() -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match input.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buffer).into_owned();
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("lws-driver-adapter-rust: cannot read stdin: {e}");
                    break;
                }
            }
        }
    });
    rx
}

/// Answers one request line; returns `false` once the adapter should exit.
async fn handle(state: &mut State, line: &str) -> bool {
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
        Ok(args) => AssertUnwindSafe(state.run(op, args))
            .catch_unwind()
            .await
            .unwrap_or_else(|panic| Err(Failure::panic(panic.as_ref()))),
        Err(e) => Err(e),
    };
    match outcome {
        Ok(result) => write(&json!({"id": id, "ok": true, "result": result})),
        Err(e) => write(&failure(id, &e)),
    }
    op != "shutdown"
}

async fn serve() {
    write(&json!({"hello": {
        "protocol": "lws-driver/1",
        "language": "rust",
        "library": LIBRARY,
        "operations": OPERATIONS,
    }}));
    let mut lines = read_lines();
    let mut state = State::new();
    while let Some(line) = lines.recv().await {
        if line.trim().is_empty() {
            continue;
        }
        if !handle(&mut state, &line).await {
            break;
        }
    }
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("lws-driver-adapter-rust: cannot start the tokio runtime: {e}");
            std::process::exit(1);
        }
    };
    runtime.block_on(serve());
    // The stdin thread may still be blocked in a read (after `shutdown`): exit regardless.
    std::process::exit(0);
}
