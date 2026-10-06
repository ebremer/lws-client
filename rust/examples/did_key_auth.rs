// SPDX-License-Identifier: MIT
//! Self-signed identity: create (or load) a key, print its did:key and the controlled
//! identifier document for an HTTPS agent, then access a protected resource via the LWS
//! token-exchange flow.
//!
//! ```sh
//! cargo run --example did_key_auth -- http://localhost:8787/root/
//! # reuse a key: LWS_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...,"d":"..."}'
//! ```

use lws_client::crypto::{Jwk, SigningKey, controlled_identifier_document};
use lws_client::{Client, Result, SelfSignedCredentials, TokenExchangeAuthenticator};

#[tokio::main]
async fn main() -> Result<()> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:8787/root/".into());

    let key = match std::env::var("LWS_PRIVATE_JWK") {
        Ok(json) => SigningKey::from_jwk(&Jwk::from_json(&serde_json::from_str(&json)?)?)?,
        Err(_) => {
            let key = SigningKey::generate_p256()?;
            println!(
                "new private JWK (keep it secret):\n{}\n",
                key.to_jwk().to_json()
            );
            key
        }
    };

    // An HTTPS agent would publish this document at its agent URI:
    let cid = controlled_identifier_document("https://id.example/bot", &key.public_jwk(), "key-1");
    println!(
        "CID document for an HTTPS agent:\n{}\n",
        serde_json::to_string_pretty(&cid)?
    );

    // A did:key agent needs no document at all.
    let credentials = SelfSignedCredentials::did_key(key);
    println!("did:key agent: {}\n", credentials.agent());

    let auth = TokenExchangeAuthenticator::new(credentials);
    let client = Client::builder().authenticator(auth.clone()).build()?;
    let metadata = client.head(target.as_str()).await?;
    println!(
        "HEAD {} -> {} (types {:?})",
        metadata.url,
        metadata.status,
        metadata.types()
    );
    if let Some(token) = auth.cached_token(&metadata.url) {
        println!(
            "access token from {} for realm {} (expires {})",
            token.issuer,
            token.realm,
            lws_client::datetime::format_rfc3339(token.expires_at)
        );
    }
    Ok(())
}
