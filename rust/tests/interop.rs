// SPDX-License-Identifier: MIT
//! End-to-end interop scenario (`conformance/scenario.md`) against the repository's mock server.
//!
//! Skipped unless `LWS_TEST_SERVER` is set, e.g.:
//!
//! ```sh
//! node testing/mock-server/server.mjs --port 8784 &
//! LWS_TEST_SERVER=http://localhost:8784 cargo test --test interop -- --nocapture
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::TryStreamExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use lws_client::crypto::SigningKey;
use lws_client::*;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

struct Delivery {
    method: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// A minimal HTTP/1.1 inbox that forwards every request and answers `204`.
async fn start_inbox() -> (Url, mpsc::UnboundedReceiver<Delivery>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbox = Url::parse(&format!("http://{}/inbox", listener.local_addr().unwrap())).unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() {
                    return;
                }
                let method = line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let mut headers = HeaderMap::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
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
                let _ = reader.read_exact(&mut body).await;
                let mut socket = reader.into_inner();
                let _ = socket.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
                let _ = tx.send(Delivery {
                    method,
                    headers,
                    body,
                });
            });
        }
    });
    (inbox, rx)
}

#[tokio::test]
async fn interop_scenario() -> Result<()> {
    let Ok(base) = std::env::var("LWS_TEST_SERVER") else {
        eprintln!("LWS_TEST_SERVER not set; skipping interop scenario");
        return Ok(());
    };
    let base = base.trim_end_matches('/').to_owned();
    let storage_id = format!("{base}/");

    // 1. Authenticate + discover.
    let credentials = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
    let agent = credentials.agent().to_owned();
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(credentials))
        .build()?;
    let storage = client.discover_storage(format!("{base}/root/")).await?;
    let root = storage.storage_root()?.clone();
    assert_eq!(root.as_str(), format!("{base}/root/"));
    assert_eq!(storage.id.as_str(), storage_id);
    let notifications = storage
        .notification_service()
        .expect("NotificationService")
        .service_endpoint
        .clone();
    let requests_svc = storage
        .access_request_service()
        .expect("AccessRequestService")
        .service_endpoint
        .clone();
    let grants_svc = storage
        .access_grant_service()
        .expect("AccessGrantService")
        .service_endpoint
        .clone();
    let index_svc = storage
        .type_index_service()
        .expect("TypeIndexService")
        .service_endpoint
        .clone();
    let search_svc = storage
        .type_search_service()
        .expect("TypeSearchService")
        .service_endpoint
        .clone();

    // 2. Container.
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let c = client
        .create_container(&root)
        .slug(&format!("interop-rust-{millis}"))
        .await?
        .location;

    // 3. Text resource.
    let h = client
        .create(&c, "Hello, LWS!", "text/plain")
        .slug("hello.txt")
        .await?
        .location;

    // 4. Read.
    let r = client.read(&h).await?;
    assert_eq!(r.text()?, "Hello, LWS!");
    let etag = r.metadata.etag.clone().expect("ETag");
    assert!(r.metadata.is_data_resource());
    assert_eq!(r.metadata.parent(), Some(&c));
    assert!(r.metadata.linkset().is_some());
    assert_eq!(
        r.metadata.storage().map(Url::as_str),
        Some(storage_id.as_str())
    );

    // 5. Conditional read.
    assert!(client.read(&h).if_none_match(&etag).await?.not_modified);

    // 6. Update with If-Match; stale ETag fails.
    client
        .update(&h, "Hello again", "text/plain")
        .if_match(&etag)
        .await?;
    let stale = client
        .update(&h, "stale", "text/plain")
        .if_match(&etag)
        .await
        .unwrap_err();
    assert!(stale.is_precondition_failed(), "{stale}");
    assert_eq!(client.read(&h).await?.text()?, "Hello again");

    // 7. JSON + JSON Patch.
    let p = client
        .create_json(&c, &json!({"name": "Alice", "age": 30}))
        .slug("profile.json")
        .resource_type("https://schema.org/Person")
        .await?
        .location;
    client
        .patch(
            &p,
            &JsonPatch::new().replace("/age", 31).add("/city", "Boston"),
        )
        .await?;
    assert_eq!(
        client.read(&p).await?.json::<Value>()?,
        json!({"name": "Alice", "age": 31, "city": "Boston"})
    );

    // 8. Linkset.
    let ls = client.read_linkset(&p).await?;
    let shape = "https://example.org/shapes/person";
    let patch = match ls.linkset.contexts.first() {
        None => JsonPatch::new().add(
            "/linkset/-",
            json!({"anchor": p.as_str(), "describedby": [{"href": shape}]}),
        ),
        Some(ctx) if ctx.targets("describedby").next().is_some() => {
            JsonPatch::new().add("/linkset/0/describedby/-", json!({"href": shape}))
        }
        Some(_) => JsonPatch::new().add("/linkset/0/describedby", json!([{"href": shape}])),
    };
    client
        .patch_linkset(&ls.url, &patch)
        .if_match(ls.etag.as_deref().unwrap_or("*"))
        .await?;
    assert!(
        client
            .read_linkset(&p)
            .await?
            .linkset
            .targets("describedby")
            .contains(&shape)
    );

    // 9. Pagination.
    for i in 0..6 {
        client
            .create(&c, format!("item {i}"), "text/plain")
            .slug(&format!("item-{i}.txt"))
            .await?;
    }
    let page = client.read_container(&c).await?;
    assert_eq!(page.total_items, Some(8));
    assert!(page.next.is_some(), "expected a paginated listing");
    let members: Vec<ContainedResource> = client.list_container(&c).try_collect().await?;
    assert_eq!(members.len(), 8);
    assert!(members.iter().any(|m| m.id == h) && members.iter().any(|m| m.id == p));

    // 10. Type index / search.
    let types: Vec<String> = client.list_types(&index_svc).try_collect().await?;
    assert!(
        types.iter().any(|t| t == "https://schema.org/Person"),
        "{types:?}"
    );
    let found: Vec<ContainedResource> = client
        .search_all(
            &search_svc,
            &TypeQuery::new().all_of(["https://schema.org/Person"]),
        )
        .try_collect()
        .await?;
    assert!(found.iter().any(|m| m.id == p), "{found:?}");
    assert!(
        client
            .accepted_query_formats(&search_svc)
            .await?
            .iter()
            .any(|f| f == "application/lws-query+json")
    );

    // 11. Notifications.
    let (inbox, mut deliveries) = start_inbox().await;
    let sub = client
        .subscribe_storage(
            &storage,
            &WebhookSubscriptionRequest::new([c.clone()], inbox.clone())
                .expires(SystemTime::now() + Duration::from_secs(600)),
        )
        .await?;
    client
        .update(&h, "Hello notifications", "text/plain")
        .await?;
    let verifier = WebhookVerifier::builder()
        .client(Client::new())
        .trusted_storage(storage.id.clone())
        .build();
    let verified = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let d = deliveries.recv().await.expect("inbox closed");
            let v = verifier
                .verify(&d.method, &inbox, &d.headers, &d.body)
                .await
                .expect("delivery verifies");
            if v.notification
                .activities
                .iter()
                .any(|a| a.is_update() && a.object.id == h.as_str())
            {
                return v;
            }
        }
    })
    .await
    .expect("webhook delivered within 5 s");
    assert_eq!(verified.storage, storage.id);
    let subs: Vec<ContainedResource> = client
        .list_subscriptions(&notifications)
        .try_collect()
        .await?;
    assert!(subs.iter().any(|s| s.id == sub.subscription), "{subs:?}");
    assert_eq!(
        client
            .get_subscription(&sub.subscription)
            .await?
            .subscription,
        sub.subscription
    );
    client.unsubscribe(&sub.subscription).await?;

    // 12. Access requests and grants.
    let policy = AccessPolicy::builder(agent.clone())
        .action("read")
        .target_resources([c.as_str()])
        .constraint(Constraint::purpose("https://purpose.example/interop"))
        .build()?;
    let request = AccessRequest::builder(storage.id.as_str())
        .policy(policy.clone())
        .build()?;
    let req_url = client.request_access(&requests_svc, &request).await?;
    let fetched = client.get_access_request(&req_url).await?;
    assert_eq!(fetched.storage, request.storage);
    assert_eq!(fetched.access, request.access);
    let listed: Vec<ContainedResource> = client
        .list_access_requests(&requests_svc)
        .try_collect()
        .await?;
    assert!(listed.iter().any(|m| m.id == req_url));
    let grant = AccessGrant::builder(storage.id.as_str())
        .policy(policy)
        .build()?;
    let grant_url = client.grant_access(&grants_svc, &grant).await?;
    assert_eq!(
        client.get_access_grant(&grant_url).await?.access,
        grant.access
    );
    let grants: Vec<ContainedResource> =
        client.list_access_grants(&grants_svc).try_collect().await?;
    assert!(grants.iter().any(|m| m.id == grant_url));
    client.revoke_access_grant(&grant_url).await?;
    client.cancel_access_request(&req_url).await?;

    // 13. Delete.
    assert!(client.delete(&c).await.unwrap_err().is_conflict());
    client.delete(&c).recursive(true).await?;
    assert!(client.read(&h).await.unwrap_err().is_not_found());

    // Ed25519 identities work too.
    let ed = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(
            SelfSignedCredentials::did_key(SigningKey::generate_ed25519()?),
        ))
        .build()?;
    assert!(ed.head(&root).await?.is_container());
    eprintln!("interop scenario passed against {base}");
    Ok(())
}
