// SPDX-License-Identifier: MIT
//! The component in Wasmtime: the engine, the compiled component and the linker, made once per
//! process, and instances of the component.
//!
//! An instance gets WASI 0.2 and `wasi:http`, nothing else: no files, no environment, no stdin
//! or stdout (stdout is the protocol's), stderr for the component's panics. Its requests go out
//! through Wasmtime's `wasi:http`, which does TLS with the webpki roots.

use std::path::Path;

use wasmtime::component::{Component, HasSelf, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpCtxView, WasiHttpView};

use crate::bindings::LwsClient;
use crate::bindings::ebremer::lws::token_source::{self, TokenKind};
use crate::bindings::ebremer::lws::types;

/// The state of an instance.
pub(crate) struct Host {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    table: ResourceTable,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for Host {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: Default::default(),
        }
    }
}

impl types::Host for Host {}

impl token_source::Host for Host {
    /// The driver hands subject tokens to `configure` (`auth.idToken`): it has none to give on
    /// demand.
    fn subject_token(
        &mut self,
        _kind: TokenKind,
        _issuer: String,
        _realm: String,
    ) -> Result<String, String> {
        Err("the driver gives subject tokens to configure, not on demand".to_owned())
    }
}

/// The compiled component, ready to instantiate.
pub(crate) struct Runtime {
    engine: Engine,
    component: Component,
    linker: Linker<Host>,
}

/// An instance of the component.
pub(crate) struct Instance {
    pub(crate) store: Store<Host>,
    pub(crate) lws: LwsClient,
}

impl Runtime {
    /// Compiles the component at `path`.
    pub(crate) fn load(path: &Path) -> wasmtime::Result<Self> {
        let engine = Engine::default();
        let component = Component::from_file(&engine, path)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_sync(&mut linker)?;
        LwsClient::add_to_linker::<Host, HasSelf<Host>>(&mut linker, |host| host)?;
        Ok(Self {
            engine,
            component,
            linker,
        })
    }

    pub(crate) fn instantiate(&self) -> wasmtime::Result<Instance> {
        let host = Host {
            wasi: WasiCtx::builder().inherit_stderr().build(),
            http: WasiHttpCtx::new(),
            table: ResourceTable::new(),
        };
        let mut store = Store::new(&self.engine, host);
        let lws = LwsClient::instantiate(&mut store, &self.component, &self.linker)?;
        Ok(Instance { store, lws })
    }
}
