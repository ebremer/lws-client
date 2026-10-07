// SPDX-License-Identifier: MIT
//! The transport on native targets: `reqwest`.

use std::time::Duration;

use bytes::Bytes;
pub(crate) use reqwest::{Body, Client as HttpClient, Response};

/// A request body of bytes.
pub(crate) fn body(bytes: Bytes) -> Body {
    Body::from(bytes)
}

/// A client that never follows a redirect, with an overall timeout per request and a
/// `User-Agent`, when given.
pub(crate) fn client(
    timeout: Option<Duration>,
    user_agent: Option<&str>,
) -> reqwest::Result<HttpClient> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    if let Some(user_agent) = user_agent {
        builder = builder.user_agent(user_agent);
    }
    builder.build()
}
