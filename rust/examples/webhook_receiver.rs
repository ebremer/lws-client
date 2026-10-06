// SPDX-License-Identifier: MIT
//! A minimal webhook inbox: subscribes to a container and verifies each signed delivery
//! (RFC 9421 + RFC 9530) with the key published in the storage description.
//!
//! ```sh
//! cargo run --example webhook_receiver -- http://localhost:8787/root/
//! # then modify something under the root container, e.g. with the quickstart example
//! ```
//!
//! The tiny HTTP/1.1 listener below only exists to keep the example dependency-free; use your
//! web framework of choice and pass its method, headers and raw body to `WebhookVerifier::verify`.

use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue};
use lws_client::{
    Client, Result, SelfSignedCredentials, TokenExchangeAuthenticator, WebhookSubscriptionRequest,
    WebhookVerifier, crypto::SigningKey,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    let topic = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:8787/root/".into());
    let credentials = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(credentials))
        .build()?;

    let storage = client.discover_storage(topic.as_str()).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let inbox = Url::parse(&format!(
        "http://{}/inbox",
        listener.local_addr().expect("addr")
    ))
    .expect("url");

    let request =
        WebhookSubscriptionRequest::new([Url::parse(&topic).expect("url")], inbox.clone())
            .expires(std::time::SystemTime::now() + Duration::from_secs(3600));
    let subscription = client.subscribe_storage(&storage, &request).await?;
    println!("subscribed: {} -> {inbox}", subscription.subscription);

    let verifier = WebhookVerifier::builder()
        .client(Client::new())
        .trusted_storage(storage.id.clone())
        .build();
    loop {
        let (socket, _) = listener.accept().await.expect("accept");
        let (method, headers, body, mut socket) = read_request(socket).await;
        match verifier.verify(&method, &inbox, &headers, &body).await {
            Ok(v) => {
                for a in &v.notification.activities {
                    println!("verified {:?} {} (key {})", a.types, a.object.id, v.key_id);
                }
                let _ = socket
                    .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
            Err(e) => {
                eprintln!("rejected delivery: {e}");
                let _ = socket
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        }
    }
}

async fn read_request(
    socket: tokio::net::TcpStream,
) -> (String, HeaderMap, Vec<u8>, tokio::net::TcpStream) {
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("request line");
    let method = line.split_whitespace().next().unwrap_or("").to_owned();
    let mut headers = HeaderMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.expect("header");
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            if let (Ok(k), Ok(v)) = (
                HeaderName::try_from(k.trim()),
                HeaderValue::try_from(v.trim()),
            ) {
                headers.append(k, v);
            }
        }
    }
    let len = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await.expect("body");
    (method, headers, body, reader.into_inner())
}
