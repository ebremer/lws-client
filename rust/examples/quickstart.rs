// SPDX-License-Identifier: MIT
//! Quick start: discover a storage, create/read/update/patch/list/delete resources.
//!
//! ```sh
//! # against the repository's mock server (node testing/mock-server/server.mjs --no-auth)
//! cargo run --example quickstart -- http://localhost:8787/root/
//! ```
//!
//! Set `LWS_DID_KEY_AUTH=1` to authenticate with a freshly generated did:key identity.

use futures_util::TryStreamExt;
use lws_client::{Client, JsonPatch, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let start = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:8787/root/".into());

    #[cfg_attr(not(feature = "crypto"), allow(unused_mut))]
    let mut builder = Client::builder();
    #[cfg(feature = "crypto")]
    if std::env::var_os("LWS_DID_KEY_AUTH").is_some() {
        use lws_client::{SelfSignedCredentials, TokenExchangeAuthenticator, crypto::SigningKey};
        let credentials = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
        println!("agent: {}", credentials.agent());
        builder = builder.authenticator(TokenExchangeAuthenticator::new(credentials));
    }
    let client = builder.build()?;

    // Discovery
    let storage = client.discover_storage(start.as_str()).await?;
    let root = storage.storage_root()?.clone();
    println!("storage {} (root {root})", storage.id);
    for s in &storage.services {
        println!("  service {:?} -> {}", s.types, s.service_endpoint);
    }

    // Create a container and two resources
    let folder = client
        .create_container(&root)
        .slug("quickstart")
        .await?
        .location;
    let note = client
        .create(&folder, "Hello, LWS!", "text/plain")
        .slug("hello.txt")
        .await?
        .location;
    let profile = client
        .create_json(&folder, &serde_json::json!({"name": "Alice", "age": 30}))
        .slug("profile.json")
        .await?
        .location;

    // Read, then update with optimistic concurrency
    let current = client.read(&note).await?;
    println!(
        "{note}: {:?} etag={:?}",
        current.text()?,
        current.metadata.etag
    );
    let etag = current.metadata.etag.clone().unwrap_or_else(|| "*".into());
    client
        .update(&note, "Hello again!", "text/plain")
        .if_match(&etag)
        .await?;
    match client
        .update(&note, "stale write", "text/plain")
        .if_match(&etag)
        .await
    {
        Err(e) if e.is_precondition_failed() => println!("stale ETag rejected as expected"),
        other => println!("unexpected: {other:?}"),
    }

    // JSON Patch
    client
        .patch(
            &profile,
            &JsonPatch::new().replace("/age", 31).add("/city", "Boston"),
        )
        .await?;
    println!("profile now {}", client.read(&profile).await?.text()?);

    // Metadata (linkset)
    let ls = client.read_linkset(&profile).await?;
    println!(
        "linkset at {} with {} links",
        ls.url,
        ls.linkset.links().len()
    );

    // List the container lazily across pages
    let items: Vec<_> = client.list_container(&folder).try_collect().await?;
    for item in &items {
        println!("  {} {:?} {:?} bytes", item.id, item.types, item.size);
    }

    // Clean up
    client.delete(&folder).recursive(true).await?;
    println!("deleted {folder}");
    Ok(())
}
