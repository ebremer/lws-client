// SPDX-License-Identifier: MIT
//! In-process HTTP tests for every client operation, using a wiremock server.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use futures_util::TryStreamExt;
use http::HeaderMap;
use lws_client::crypto::{SigningKey, VerifyingKey, jwt};
use lws_client::*;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CONTAINER: &str = "<https://www.w3.org/ns/lws#Container>; rel=\"type\"";
const DATA: &str = "<https://www.w3.org/ns/lws#DataResource>; rel=\"type\"";

fn url(server: &MockServer, p: &str) -> Url {
    Url::parse(&format!("{}{p}", server.uri())).unwrap()
}

fn header_str<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

fn all_headers(req: &Request, name: &str) -> Vec<String> {
    req.headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

async fn requests(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap()
}

fn storage_json(base: &str) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
        "id": format!("{base}/"),
        "type": "Storage",
        "service": [
            {"type": "StorageRoot", "serviceEndpoint": format!("{base}/root/")},
            {"type": "NotificationService", "serviceEndpoint": format!("{base}/notifications/"), "subscriptionType": ["WebhookSubscription"]},
        ]
    })
}

// ---------------------------------------------------------------- discovery

#[tokio::test]
async fn discover_storage_follows_storage_link() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("HEAD"))
        .and(path("/root/notes/"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("link", "</>; rel=\"https://www.w3.org/ns/lws#storage\"")
                .append_header("link", CONTAINER),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(storage_json(&base).to_string(), "application/lws+cid"),
        )
        .mount(&server)
        .await;
    let client = Client::new();
    let sd = client
        .discover_storage(url(&server, "/root/notes/"))
        .await
        .unwrap();
    assert_eq!(sd.storage_root().unwrap(), &url(&server, "/root/"));
    assert!(
        sd.notification_service()
            .unwrap()
            .supports_subscription_type("WebhookSubscription")
    );
    let reqs = requests(&server).await;
    assert!(
        header_str(&reqs[1], "accept")
            .unwrap()
            .starts_with("application/lws+cid")
    );
    assert!(
        header_str(&reqs[0], "user-agent")
            .unwrap()
            .starts_with("lws-client-rust/")
    );
}

#[tokio::test]
async fn discover_storage_uses_link_on_401_and_get_fallback() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("HEAD"))
        .and(path("/private/"))
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("link", "</>; rel=\"https://www.w3.org/ns/lws#storage\""),
        )
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/nohead"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/nohead"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("link", "</>; rel=\"https://www.w3.org/ns/lws#storage\"")
                .set_body_string("x"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(storage_json(&base)))
        .mount(&server)
        .await;
    let client = Client::new();
    assert_eq!(
        client
            .discover_storage(url(&server, "/private/"))
            .await
            .unwrap()
            .id,
        url(&server, "/")
    );
    assert_eq!(
        client
            .discover_storage(url(&server, "/nohead"))
            .await
            .unwrap()
            .id,
        url(&server, "/")
    );
}

// ---------------------------------------------------------------- reading

#[tokio::test]
async fn read_head_conditional_and_range() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/a.txt"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304).insert_header("etag", "\"v1\""))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/a.txt"))
        .and(header("range", "bytes=0-4"))
        .respond_with(
            ResponseTemplate::new(206)
                .insert_header("content-range", "bytes 0-4/11")
                .set_body_string("Hello"),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let ok = ResponseTemplate::new(200)
        .insert_header("etag", "\"v1\"")
        .insert_header("last-modified", "Tue, 15 Nov 1994 08:12:31 GMT")
        .append_header(
            "link",
            "</a.txt.meta>; rel=\"linkset\"; type=\"application/linkset+json\"",
        )
        .append_header("link", "</>; rel=\"up\"")
        .append_header("link", DATA)
        .set_body_raw("Hello world", "text/plain; charset=utf-8");
    Mock::given(method("GET"))
        .and(path("/a.txt"))
        .respond_with(ok.clone())
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/a.txt"))
        .respond_with(ok)
        .mount(&server)
        .await;

    let client = Client::new();
    let r = client.read(url(&server, "/a.txt")).await.unwrap();
    assert_eq!(r.text().unwrap(), "Hello world");
    assert!(!r.not_modified);
    let m = &r.metadata;
    assert_eq!(m.etag.as_deref(), Some("\"v1\""));
    assert!(m.is_data_resource() && !m.is_container());
    assert_eq!(m.linkset().unwrap(), &url(&server, "/a.txt.meta"));
    assert_eq!(m.parent().unwrap(), &url(&server, "/"));
    assert_eq!(m.media_type().as_deref(), Some("text/plain"));
    assert!(m.last_modified_time().is_some());

    let nm = client
        .read(url(&server, "/a.txt"))
        .if_none_match("\"v1\"")
        .await
        .unwrap();
    assert!(nm.not_modified);
    assert!(nm.body.is_empty());

    let part = client
        .read(url(&server, "/a.txt"))
        .range(0, Some(4))
        .await
        .unwrap();
    assert!(part.is_partial());
    assert_eq!(part.text().unwrap(), "Hello");
    assert_eq!(part.metadata.content_range(), Some("bytes 0-4/11"));

    let head = client.head(url(&server, "/a.txt")).await.unwrap();
    assert_eq!(head.etag.as_deref(), Some("\"v1\""));

    let mut streaming = client
        .read(url(&server, "/a.txt"))
        .send_streaming()
        .await
        .unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = streaming.chunk().await.unwrap() {
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(collected, b"Hello world");
}

fn page(server: &MockServer, n: usize, total: usize) -> ResponseTemplate {
    let ids: Vec<Value> = (0..2).map(|i| json!({"id": format!("item-{n}-{i}"), "type": "DataResource", "format": "text/plain", "size": 3})).collect();
    let mut t = ResponseTemplate::new(200)
        .append_header("link", CONTAINER)
        .append_header("link", format!("<{}/c/?page=1>; rel=\"first\"", server.uri()))
        .set_body_raw(json!({"@context": "https://www.w3.org/ns/lws/v1", "id": "/c/", "type": "Container", "totalItems": total * 2, "items": ids}).to_string(), "application/lws+json");
    if n < total {
        t = t.append_header("link", format!("</c/?page={}>; rel=\"next\"", n + 1));
    }
    t
}

#[tokio::test]
async fn container_pagination_across_three_pages() {
    let server = MockServer::start().await;
    for n in 2..=3 {
        Mock::given(method("GET"))
            .and(path("/c/"))
            .and(query_param("page", n.to_string()))
            .respond_with(page(&server, n, 3))
            .with_priority(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/c/"))
        .respond_with(page(&server, 1, 3))
        .mount(&server)
        .await;
    let client = Client::new();
    let first = client.read_container(url(&server, "/c/")).await.unwrap();
    assert_eq!(first.total_items, Some(6));
    assert_eq!(first.id, url(&server, "/c/"));
    assert_eq!(first.next.as_ref().unwrap(), &url(&server, "/c/?page=2"));
    assert_eq!(first.items[0].id, url(&server, "/c/item-1-0"));
    let all: Vec<ContainedResource> = client
        .list_container(url(&server, "/c/"))
        .try_collect()
        .await
        .unwrap();
    assert_eq!(all.len(), 6);
    assert_eq!(all[5].id, url(&server, "/c/item-3-1"));
    let reqs = requests(&server).await;
    assert!(
        reqs.iter()
            .all(|r| header_str(r, "accept") == Some("application/lws+json"))
    );
}

#[tokio::test]
async fn pagination_loop_is_detected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/loop/"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("link", CONTAINER)
                .append_header("link", "</loop/>; rel=\"next\"")
                .set_body_raw(r#"{"type":"Container","items":[]}"#, "application/lws+json"),
        )
        .mount(&server)
        .await;
    let result: Result<Vec<ContainedResource>> = Client::new()
        .list_container(url(&server, "/loop/"))
        .try_collect()
        .await;
    assert!(result.unwrap_err().is_protocol());
}

// ---------------------------------------------------------------- writing

#[tokio::test]
async fn create_resources_and_containers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/c/"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("location", "/c/hello.txt")
                .append_header(
                    "link",
                    "</c/hello.txt.meta>; rel=\"linkset\"; type=\"application/linkset+json\"",
                )
                .append_header("link", "</c/>; rel=\"up\""),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/nolocation/"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;
    let client = Client::new();
    let created = client
        .create(url(&server, "/c/"), "Hello, LWS!", "text/plain")
        .slug("Grüße.txt")
        .resource_type("https://schema.org/Note")
        .link(Link::new(
            Url::parse("https://example.org/shape").unwrap(),
            "describedby",
        ))
        .await
        .unwrap();
    assert_eq!(created.location, url(&server, "/c/hello.txt"));
    assert_eq!(
        created.metadata.linkset().unwrap(),
        &url(&server, "/c/hello.txt.meta")
    );
    let folder = client
        .create_container(url(&server, "/c/"))
        .slug("notes")
        .await
        .unwrap();
    assert_eq!(folder.location, url(&server, "/c/hello.txt"));
    let json_doc = client
        .create_json(url(&server, "/c/"), &json!({"a": 1}))
        .await
        .unwrap();
    assert_eq!(json_doc.location, url(&server, "/c/hello.txt"));
    assert!(
        client
            .create(url(&server, "/nolocation/"), "x", "text/plain")
            .await
            .unwrap_err()
            .is_protocol()
    );

    let reqs = requests(&server).await;
    assert_eq!(header_str(&reqs[0], "content-type"), Some("text/plain"));
    assert_eq!(header_str(&reqs[0], "slug"), Some("Gr%C3%BC%C3%9Fe.txt"));
    assert_eq!(reqs[0].body, b"Hello, LWS!");
    let links = all_headers(&reqs[0], "link");
    assert!(links.contains(&"<https://schema.org/Note>; rel=\"type\"".to_owned()));
    assert!(links.contains(&"<https://example.org/shape>; rel=\"describedby\"".to_owned()));
    assert_eq!(
        all_headers(&reqs[1], "link"),
        vec!["<https://www.w3.org/ns/lws#Container>; rel=\"type\"".to_owned()]
    );
    assert_eq!(header_str(&reqs[1], "content-length"), Some("0"));
    assert!(reqs[1].body.is_empty());
    assert_eq!(
        header_str(&reqs[2], "content-type"),
        Some("application/json")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[2].body).unwrap(),
        json!({"a": 1})
    );
}

#[tokio::test]
async fn update_patch_delete_and_preconditions() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/r"))
        .and(header("if-match", "\"old\""))
        .respond_with(ResponseTemplate::new(412).set_body_raw(
            r#"{"title":"Precondition Failed","status":412}"#,
            "application/problem+json",
        ))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/r"))
        .respond_with(ResponseTemplate::new(204).insert_header("etag", "\"v2\""))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/r"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v3\"")
                .set_body_string("{}"),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/full/"))
        .and(header("depth", "infinity"))
        .respond_with(ResponseTemplate::new(204))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/full/"))
        .respond_with(ResponseTemplate::new(409).set_body_raw(
            r#"{"type":"https://s.example/not-empty","title":"Container not empty","status":409,"count":3}"#,
            "application/problem+json",
        ))
        .mount(&server)
        .await;
    let client = Client::new();
    let r = client
        .update(url(&server, "/r"), "new", "text/plain")
        .if_match("\"v1\"")
        .link(Link::new(
            Url::parse("https://example.org/l").unwrap(),
            "license",
        ))
        .set_linkset(true)
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 204);
    assert_eq!(r.etag.as_deref(), Some("\"v2\""));
    let stale = client
        .update(url(&server, "/r"), "new", "text/plain")
        .if_match("\"old\"")
        .await
        .unwrap_err();
    assert!(stale.is_precondition_failed());
    assert_eq!(
        stale.problem().unwrap().title.as_deref(),
        Some("Precondition Failed")
    );

    let p = client
        .patch(url(&server, "/r"), &JsonPatch::new().replace("/age", 31))
        .if_match("\"v2\"")
        .await
        .unwrap();
    assert_eq!(p.etag.as_deref(), Some("\"v3\""));
    client
        .patch_with(
            url(&server, "/r"),
            "INSERT DATA {}",
            "application/sparql-update",
        )
        .await
        .unwrap();

    let err = client.delete(url(&server, "/full/")).await.unwrap_err();
    assert!(err.is_conflict());
    assert_eq!(err.problem().unwrap().extensions["count"], json!(3));
    client
        .delete(url(&server, "/full/"))
        .recursive(true)
        .if_match("\"c1\"")
        .await
        .unwrap();

    let reqs = requests(&server).await;
    assert_eq!(header_str(&reqs[0], "prefer"), Some("set-linkset"));
    assert_eq!(
        all_headers(&reqs[0], "link"),
        vec!["<https://example.org/l>; rel=\"license\"".to_owned()]
    );
    assert_eq!(
        header_str(&reqs[2], "content-type"),
        Some("application/json-patch+json")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[2].body).unwrap(),
        json!([{"op": "replace", "path": "/age", "value": 31}])
    );
    assert_eq!(
        header_str(&reqs[3], "content-type"),
        Some("application/sparql-update")
    );
    assert_eq!(header_str(&reqs[5], "if-match"), Some("\"c1\""));
}

#[tokio::test]
async fn error_mapping() {
    let server = MockServer::start().await;
    for code in [
        400u16, 401, 403, 404, 405, 406, 409, 410, 412, 415, 422, 501, 507, 500, 418,
    ] {
        let mut t = ResponseTemplate::new(code);
        if code == 405 {
            t = t.insert_header("allow", "GET, HEAD");
        }
        if code == 415 {
            t = t.insert_header("accept-patch", "application/json-patch+json");
        }
        if code == 401 {
            t = t.insert_header("www-authenticate", "Basic realm=\"x\"");
        }
        Mock::given(method("GET"))
            .and(path(format!("/s{code}")))
            .respond_with(t)
            .mount(&server)
            .await;
    }
    let client = Client::new();
    for code in [
        400u16, 401, 403, 404, 405, 406, 409, 410, 412, 415, 422, 501, 507, 500, 418,
    ] {
        let err = client
            .read(url(&server, &format!("/s{code}")))
            .await
            .unwrap_err();
        assert_eq!(err.status().unwrap().as_u16(), code);
        let ok = match code {
            400 => matches!(err, Error::BadRequest(_)),
            401 => {
                matches!(err, Error::Unauthorized(_))
                    && err.http_error().unwrap().challenges[0].scheme == "Basic"
            }
            403 => err.is_forbidden(),
            404 => err.is_not_found(),
            405 => matches!(&err, Error::MethodNotAllowed(e) if e.allow() == ["GET", "HEAD"]),
            406 => matches!(err, Error::NotAcceptable(_)),
            409 => err.is_conflict(),
            410 => err.is_gone(),
            412 => err.is_precondition_failed(),
            415 => {
                matches!(&err, Error::UnsupportedMediaType(e) if e.accept_patch() == ["application/json-patch+json"])
            }
            422 => matches!(err, Error::UnprocessableContent(_)),
            501 => matches!(err, Error::NotImplemented(_)),
            507 => matches!(err, Error::InsufficientStorage(_)),
            _ => matches!(err, Error::Http(_)),
        };
        assert!(ok, "status {code} mapped to {err:?}");
    }
}

// ---------------------------------------------------------------- linksets

#[tokio::test]
async fn linkset_read_patch_put() {
    let server = MockServer::start().await;
    let anchor = format!("{}/doc", server.uri());
    Mock::given(method("HEAD"))
        .and(path("/doc"))
        .respond_with(
            ResponseTemplate::new(200).append_header("link", "</doc.meta>; rel=\"linkset\""),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/doc.meta"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"ls1\"")
                .insert_header("allow", "GET, HEAD, PATCH")
                .insert_header("accept-patch", "application/json-patch+json")
                .set_body_raw(json!({"linkset": [{"anchor": anchor, "describedby": [{"href": "https://example.org/s"}]}]}).to_string(), "application/linkset+json"),
        )
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/doc.meta"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/doc.meta"))
        .respond_with(ResponseTemplate::new(405).insert_header("allow", "GET, HEAD, PATCH"))
        .mount(&server)
        .await;
    let client = Client::new();
    let doc = client.read_linkset(url(&server, "/doc")).await.unwrap();
    assert_eq!(doc.url, url(&server, "/doc.meta"));
    assert_eq!(doc.etag.as_deref(), Some("\"ls1\""));
    assert_eq!(doc.allow, ["GET", "HEAD", "PATCH"]);
    assert_eq!(
        doc.linkset.targets("describedby"),
        ["https://example.org/s"]
    );
    let patch = JsonPatch::new().add(
        JsonPointer::root().push("linkset").push(0).push("license"),
        json!([{"href": "https://example.org/l"}]),
    );
    client
        .patch_linkset(&doc.url, &patch)
        .if_match(doc.etag.as_deref().unwrap())
        .await
        .unwrap();
    let err = client
        .update_linkset(&doc.url, &doc.linkset)
        .await
        .unwrap_err();
    assert!(matches!(&err, Error::MethodNotAllowed(e) if e.allow().contains(&"PATCH".to_owned())));
    let reqs = requests(&server).await;
    assert_eq!(
        header_str(&reqs[1], "accept"),
        Some("application/linkset+json")
    );
    assert_eq!(
        header_str(&reqs[2], "content-type"),
        Some("application/json-patch+json")
    );
    assert_eq!(header_str(&reqs[2], "if-match"), Some("\"ls1\""));
    assert_eq!(
        header_str(&reqs[3], "content-type"),
        Some("application/linkset+json")
    );
}

// ---------------------------------------------------------------- authentication

struct AuthServer {
    server: MockServer,
    exchanges: Arc<AtomicUsize>,
}

/// A storage that requires `Bearer token-N` and an AS that issues `token-N` on each exchange,
/// verifying the self-signed JWT.
async fn auth_server(realm_path: &str, token_types: Value) -> AuthServer {
    let server = MockServer::start().await;
    let base = server.uri();
    let exchanges = Arc::new(AtomicUsize::new(0));
    let realm = format!("{base}{realm_path}");
    Mock::given(method("GET"))
        .and(path("/.well-known/lws-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": base,
            "token_endpoint": format!("{base}/token"),
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
            "subject_token_types_supported": token_types,
        })))
        .mount(&server)
        .await;
    let counter = exchanges.clone();
    let expected_resource = realm.clone();
    let issuer = base.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |req: &Request| {
            let form: std::collections::HashMap<String, String> = url::form_urlencoded::parse(&req.body).into_owned().collect();
            assert_eq!(form["grant_type"], "urn:ietf:params:oauth:grant-type:token-exchange");
            assert_eq!(form["resource"], expected_resource);
            if form["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt" {
                let token = &form["subject_token"];
                let (_, claims) = jwt::decode_unverified(token).unwrap();
                let sub = claims["sub"].as_str().unwrap();
                let key = VerifyingKey::from_did_key(sub).unwrap();
                let (header, claims) = jwt::verify(token, &key).unwrap();
                assert_eq!(header["typ"], "JWT");
                assert!(header["kid"].as_str().unwrap().starts_with(sub));
                assert_eq!(claims["iss"], claims["sub"]);
                assert_eq!(claims["client_id"], claims["sub"]);
                assert_eq!(claims["aud"], json!([issuer]));
                assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
                assert!(claims["jti"].is_string());
            }
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            ResponseTemplate::new(200).set_body_json(json!({"access_token": format!("token-{n}"), "token_type": "Bearer", "expires_in": 300}))
        })
        .mount(&server)
        .await;
    let challenge = format!("Bearer as_uri=\"{base}\", realm=\"{realm}\", error=\"invalid_token\"");
    // token-1 is revoked by the storage; token-2 and later are accepted.
    for t in ["token-2", "token-3"] {
        Mock::given(path_prefix_matcher("/data/"))
            .and(header("authorization", format!("Bearer {t}").as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"e\"")
                    .set_body_string("secret"),
            )
            .with_priority(1)
            .mount(&server)
            .await;
    }
    Mock::given(path_prefix_matcher("/data/"))
        .respond_with(
            ResponseTemplate::new(401).insert_header("www-authenticate", challenge.as_str()),
        )
        .mount(&server)
        .await;
    AuthServer { server, exchanges }
}

fn path_prefix_matcher(prefix: &'static str) -> impl wiremock::Match {
    move |req: &Request| req.url.path().starts_with(prefix)
}

#[tokio::test]
async fn token_exchange_flow_with_self_signed_did_key() {
    let s = auth_server("/data/", json!(["urn:ietf:params:oauth:token-type:jwt"])).await;
    let creds = SelfSignedCredentials::did_key(SigningKey::generate_p256().unwrap());
    let auth = TokenExchangeAuthenticator::new(creds);
    let client = Client::builder()
        .authenticator(auth.clone())
        .build()
        .unwrap();

    // 1st request: 401 → exchange (token-1) → retry → 401 again (token-1 revoked) → error.
    let err = client.read(url(&s.server, "/data/a")).await.unwrap_err();
    assert!(err.is_unauthorized(), "{err:?}");
    assert_eq!(s.exchanges.load(Ordering::SeqCst), 1);

    // 2nd request: proactive token-1 → 401 invalid_token → drop it, exchange (token-2) → 200.
    let r = client.read(url(&s.server, "/data/b")).await.unwrap();
    assert_eq!(r.text().unwrap(), "secret");
    assert_eq!(s.exchanges.load(Ordering::SeqCst), 2);

    // Further requests reuse token-2 proactively: no new exchange.
    client.read(url(&s.server, "/data/c")).await.unwrap();
    client.head(url(&s.server, "/data/d")).await.unwrap();
    assert_eq!(s.exchanges.load(Ordering::SeqCst), 2);
    assert_eq!(
        auth.cached_token(&url(&s.server, "/data/x")).unwrap().token,
        "token-2"
    );

    let reqs = requests(&s.server).await;
    let data: Vec<&Request> = reqs
        .iter()
        .filter(|r| r.url.path().starts_with("/data/"))
        .collect();
    assert_eq!(
        header_str(data.last().unwrap(), "authorization"),
        Some("Bearer token-2")
    );
    assert!(header_str(data[0], "authorization").is_none());
}

#[tokio::test]
async fn token_exchange_with_ed25519_and_openid() {
    let s = auth_server(
        "/data/",
        json!([
            "urn:ietf:params:oauth:token-type:jwt",
            "urn:ietf:params:oauth:token-type:id_token"
        ]),
    )
    .await;
    // Pre-burn token-1 so the next exchange yields an accepted token.
    let burn = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(OpenIdCredentials::new(
            "id-token",
        )))
        .build()
        .unwrap();
    let _ = burn.read(url(&s.server, "/data/a")).await;
    let creds = SelfSignedCredentials::did_key(SigningKey::generate_ed25519().unwrap());
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(creds))
        .build()
        .unwrap();
    assert_eq!(
        client
            .read(url(&s.server, "/data/b"))
            .await
            .unwrap()
            .text()
            .unwrap(),
        "secret"
    );
    let reqs = requests(&s.server).await;
    let forms: Vec<String> = reqs
        .iter()
        .filter(|r| r.url.path() == "/token")
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect();
    assert!(forms[0].contains("subject_token=id-token"));
    assert!(
        forms[0].contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token")
    );
}

#[tokio::test]
async fn realm_check_rejects_foreign_realm() {
    let s = auth_server("/other/", json!(["urn:ietf:params:oauth:token-type:jwt"])).await;
    let creds = SelfSignedCredentials::did_key(SigningKey::generate_p256().unwrap());
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(creds))
        .build()
        .unwrap();
    let err = client.read(url(&s.server, "/data/a")).await.unwrap_err();
    assert!(err.is_authentication(), "{err:?}");
    assert_eq!(s.exchanges.load(Ordering::SeqCst), 0);
}

/// The metadata and token requests never follow a redirect: a 307 or 308 would carry the
/// subject token on to its target.
#[tokio::test]
async fn authorization_server_redirects_are_not_followed() {
    for redirected in ["/.well-known/lws-configuration", "/token"] {
        let server = MockServer::start().await;
        let thief = MockServer::start().await;
        let base = server.uri();
        Mock::given(path(redirected))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}{redirected}", thief.uri()).as_str()),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/lws-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "token_endpoint": format!("{base}/token"),
            })))
            .mount(&server)
            .await;
        Mock::given(path_prefix_matcher("/data/"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!("Bearer as_uri=\"{base}\", realm=\"{base}/data/\"").as_str(),
            ))
            .mount(&server)
            .await;
        let client = Client::builder()
            .authenticator(TokenExchangeAuthenticator::new(OpenIdCredentials::new(
                "id-token",
            )))
            .build()
            .unwrap();
        let err = client.read(url(&server, "/data/a")).await.unwrap_err();
        assert!(err.is_authentication(), "{redirected}: {err:?}");
        assert!(
            requests(&thief).await.is_empty(),
            "{redirected}: the redirect target received a request"
        );
    }
}

#[tokio::test]
async fn unsupported_subject_token_type_is_rejected() {
    let s = auth_server(
        "/data/",
        json!(["urn:ietf:params:oauth:token-type:id_token"]),
    )
    .await;
    let creds = SelfSignedCredentials::did_key(SigningKey::generate_p256().unwrap());
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(creds))
        .build()
        .unwrap();
    let err = client.read(url(&s.server, "/data/a")).await.unwrap_err();
    assert!(err.is_authentication(), "{err:?}");
    assert_eq!(s.exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn insecure_authorization_server_and_policy_filter() {
    let server = MockServer::start().await;
    let realm = format!("{}/", server.uri());
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!("Bearer as_uri=\"http://as.example\", realm=\"{realm}\"").as_str(),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/y"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!("Bearer as_uri=\"{}\", realm=\"{realm}\"", server.uri()).as_str(),
        ))
        .mount(&server)
        .await;
    let auth = TokenExchangeAuthenticator::builder(OpenIdCredentials::new("t"))
        .authorization_server_filter(|_, _| false)
        .build();
    let client = Client::builder().authenticator(auth).build().unwrap();
    let err = client.read(url(&server, "/x")).await.unwrap_err();
    assert!(err.to_string().contains("insecure"), "{err}");
    let err = client.read(url(&server, "/y")).await.unwrap_err();
    assert!(err.to_string().contains("policy"), "{err}");
}

#[tokio::test]
async fn token_endpoint_errors_and_issuer_mismatch() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/lws-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"issuer": base, "token_endpoint": format!("{base}/token")})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/lws-configuration/evil"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"issuer": "https://evil.example", "token_endpoint": format!("{base}/token")}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({"error": "invalid_request", "error_description": "unknown storage"}),
        ))
        .mount(&server)
        .await;
    for (p, as_uri) in [("/a", base.clone()), ("/b", format!("{base}/evil"))] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!("Bearer as_uri=\"{as_uri}\", realm=\"{base}/\"").as_str(),
            ))
            .mount(&server)
            .await;
    }
    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(SamlCredentials::from_xml(
            "<saml/>",
        )))
        .build()
        .unwrap();
    match client.read(url(&server, "/a")).await.unwrap_err() {
        Error::Authentication {
            error,
            error_description,
            ..
        } => {
            assert_eq!(error.as_deref(), Some("invalid_request"));
            assert_eq!(error_description.as_deref(), Some("unknown storage"));
        }
        e => panic!("{e:?}"),
    }
    let err = client.read(url(&server, "/b")).await.unwrap_err();
    assert!(
        err.is_authentication() && err.to_string().contains("does not match"),
        "{err}"
    );
    let form = requests(&server)
        .await
        .into_iter()
        .find(|r| r.url.path() == "/token")
        .unwrap();
    assert!(String::from_utf8(form.body).unwrap().contains(&format!(
        "subject_token={}",
        lws_client::auth::encode_saml_assertion(b"<saml/>")
    )));
}

#[tokio::test]
async fn bearer_token_authenticator() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/in/x"))
        .and(header("authorization", "Bearer abc"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/out/x"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let auth = BearerTokenAuthenticator::new("abc").with_realm(url(&server, "/in/"));
    let client = Client::builder().authenticator(auth).build().unwrap();
    client.read(url(&server, "/in/x")).await.unwrap();
    client.read(url(&server, "/out/x")).await.unwrap();
    let reqs = requests(&server).await;
    assert!(
        header_str(&reqs[1], "authorization").is_none(),
        "token must not leave its realm"
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let rotating = BearerTokenAuthenticator::from_fn(move || {
        let n = c.fetch_add(1, Ordering::SeqCst);
        async move {
            Ok(if n == 0 {
                "stale".to_owned()
            } else {
                "abc".to_owned()
            })
        }
    });
    Mock::given(method("GET"))
        .and(path("/rot"))
        .and(header("authorization", "Bearer abc"))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rot"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let client = Client::builder().authenticator(rotating).build().unwrap();
    client.read(url(&server, "/rot")).await.unwrap();
}

// ---------------------------------------------------------------- notifications, access, index

#[tokio::test]
async fn subscriptions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/notifications/"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("location", "/notifications/s1")
                .set_body_raw(json!({"type": "WebhookSubscription", "subscription": "/notifications/s1", "expires": "2026-06-09T12:00:00Z"}).to_string(), "application/lws+json"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/notifications/s1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"type": "WebhookSubscription", "subscription": "/notifications/s1"}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/notifications/s1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/notifications/"))
        .respond_with(ResponseTemplate::new(200).append_header("link", CONTAINER).set_body_raw(
            json!({"type": "Container", "items": [{"id": "s1", "type": ["DataResource", "WebhookSubscription"]}]}).to_string(),
            "application/lws+json",
        ))
        .mount(&server)
        .await;
    let client = Client::new();
    let svc = url(&server, "/notifications/");
    let req = WebhookSubscriptionRequest::new(
        [url(&server, "/root/")],
        Url::parse("https://receiver.example/hook").unwrap(),
    )
    .expires_raw("2026-06-09T12:00:00Z");
    let sub = client.subscribe(&svc, &req).await.unwrap();
    assert_eq!(sub.subscription, url(&server, "/notifications/s1"));
    assert!(sub.expires.is_some());
    assert_eq!(
        client
            .get_subscription(&sub.subscription)
            .await
            .unwrap()
            .subscription_type,
        "WebhookSubscription"
    );
    let listed: Vec<ContainedResource> =
        client.list_subscriptions(&svc).try_collect().await.unwrap();
    assert_eq!(listed[0].id, sub.subscription);
    client.unsubscribe(&sub.subscription).await.unwrap();
    let reqs = requests(&server).await;
    assert_eq!(
        header_str(&reqs[0], "content-type"),
        Some("application/lws+json")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[0].body).unwrap(),
        req.to_json()
    );
}

#[tokio::test]
async fn access_requests_and_grants() {
    let server = MockServer::start().await;
    let request = AccessRequest::builder(format!("{}/", server.uri()))
        .policy(
            AccessPolicy::builder("did:key:z6Mk")
                .action("read")
                .target_resources([format!("{}/root/", server.uri())])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let grant = AccessGrant::builder(format!("{}/", server.uri()))
        .policy(request.access[0].clone())
        .build()
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/requests/"))
        .respond_with(ResponseTemplate::new(201).insert_header("location", "/requests/1"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/grants/"))
        .respond_with(ResponseTemplate::new(201).insert_header("location", "/grants/1"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/requests/1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(request.to_json()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/grants/1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(grant.to_json()))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = Client::new();
    let r = client
        .request_access(url(&server, "/requests/"), &request)
        .await
        .unwrap();
    assert_eq!(r, url(&server, "/requests/1"));
    assert_eq!(client.get_access_request(&r).await.unwrap(), request);
    let g = client
        .grant_access(url(&server, "/grants/"), &grant)
        .await
        .unwrap();
    assert_eq!(client.get_access_grant(&g).await.unwrap(), grant);
    client.revoke_access_grant(&g).await.unwrap();
    client.cancel_access_request(&r).await.unwrap();
    let reqs = requests(&server).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[0].body).unwrap(),
        request.to_json()
    );
}

#[tokio::test]
async fn type_index_and_search_with_query_method() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/types/index"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(json!({"type": "TypeIndex", "totalItems": 3, "items": [{"id": "https://schema.org/Event"}]}).to_string(), "application/lws+json"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/types/index"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", "</types/index?page=2>; rel=\"next\"")
                .set_body_raw(json!({"type": "TypeIndex", "totalItems": 3, "items": [{"id": "https://schema.org/Person"}, {"id": "https://schema.org/Note"}]}).to_string(), "application/lws+json"),
        )
        .mount(&server)
        .await;
    Mock::given(method("QUERY"))
        .and(path("/types/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{base}/types/search?cursor=b>; rel=\"next\"").as_str())
                .set_body_raw(json!({"type": "ContainerPage", "totalItems": 2, "items": [{"id": "/data/p1", "type": ["DataResource", "https://schema.org/Person"]}]}).to_string(), "application/lws+json"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/types/search"))
        .and(query_param("cursor", "b"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(json!({"type": "ContainerPage", "totalItems": 2, "items": [{"id": "/data/p2", "type": "DataResource"}]}).to_string(), "application/lws+json"))
        .mount(&server)
        .await;
    Mock::given(method("OPTIONS"))
        .and(path("/types/search"))
        .respond_with(
            ResponseTemplate::new(204)
                .insert_header("allow", "OPTIONS, QUERY")
                .insert_header(
                    "accept-query",
                    "application/lws-query+json, \"application/sparql-query\"",
                ),
        )
        .mount(&server)
        .await;
    let client = Client::new();
    let types: Vec<String> = client
        .list_types(url(&server, "/types/index"))
        .try_collect()
        .await
        .unwrap();
    assert_eq!(
        types,
        [
            "https://schema.org/Person",
            "https://schema.org/Note",
            "https://schema.org/Event"
        ]
    );
    let q = TypeQuery::new().all_of(["https://schema.org/Person"]);
    let first = client
        .search_types(url(&server, "/types/search"), &q)
        .await
        .unwrap();
    assert_eq!(first.items[0].id, url(&server, "/data/p1"));
    assert_eq!(first.total_items, Some(2));
    let all: Vec<ContainedResource> = client
        .search_all(url(&server, "/types/search"), &q)
        .try_collect()
        .await
        .unwrap();
    assert_eq!(
        all.iter().map(|i| i.id.path()).collect::<Vec<_>>(),
        ["/data/p1", "/data/p2"]
    );
    assert_eq!(
        client
            .accepted_query_formats(url(&server, "/types/search"))
            .await
            .unwrap(),
        ["application/lws-query+json", "application/sparql-query"]
    );
    let bad = client
        .search_types(
            url(&server, "/types/search"),
            &TypeQuery::new().all_of(["Person"]),
        )
        .await
        .unwrap_err();
    assert!(matches!(bad, Error::InvalidInput(_)));

    let reqs = requests(&server).await;
    let query = reqs.iter().find(|r| r.method.as_str() == "QUERY").unwrap();
    assert_eq!(
        header_str(query, "content-type"),
        Some("application/lws-query+json")
    );
    assert_eq!(header_str(query, "accept"), Some("application/lws+json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&query.body).unwrap(),
        json!({"type": ["https://schema.org/Person"]})
    );
}

// ---------------------------------------------------------------- webhook verification with fetching

fn sign_delivery(key: &SigningKey, keyid: &str, inbox: &Url, body: &[u8]) -> HeaderMap {
    use base64::Engine as _;
    use sha2::Digest as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/lws+json".parse().unwrap());
    headers.insert(
        "content-digest",
        format!("sha-256=:{}:", b64.encode(sha2::Sha256::digest(body)))
            .parse()
            .unwrap(),
    );
    let created = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let input = format!(
        "sig1=(\"@method\" \"@scheme\" \"@authority\" \"@path\" \"content-type\" \"content-digest\");created={created};keyid=\"{keyid}\";alg=\"{}\"",
        key.algorithm().http_signature_alg()
    );
    let dict = lws_client::headers::structured::parse_dictionary(&input).unwrap();
    let lws_client::headers::structured::MemberValue::InnerList(params) = dict.get("sig1").unwrap()
    else {
        panic!()
    };
    let base = lws_client::webhook::signature_base("POST", inbox, &headers, params).unwrap();
    headers.insert("signature-input", input.parse().unwrap());
    headers.insert(
        "signature",
        format!("sig1=:{}:", b64.encode(key.sign(base.as_bytes())))
            .parse()
            .unwrap(),
    );
    headers
}

#[tokio::test]
async fn webhook_verifier_fetches_and_caches_keys() {
    let server = MockServer::start().await;
    let storage = format!("{}/", server.uri());
    let key = SigningKey::generate_p256().unwrap();
    let description = json!({
        "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
        "id": storage,
        "type": "Storage",
        "verificationMethod": [{"id": "#k1", "type": "JsonWebKey", "controller": storage, "publicKeyJwk": key.public_jwk().to_json()}],
        "authentication": ["#k1"],
        "service": [{"type": "StorageRoot", "serviceEndpoint": format!("{storage}root/")}],
    });
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(description))
        .expect(2)
        .mount(&server)
        .await;
    let inbox = Url::parse("https://receiver.example:8443/hooks/lws").unwrap();
    let body = json!({
        "type": "Notification", "storage": storage,
        "activity": {"id": "a1", "type": ["Update"], "object": {"id": format!("{storage}root/x"), "type": ["DataResource"]}, "published": "2026-10-05T00:00:00Z"}
    })
    .to_string();
    let headers = sign_delivery(&key, &format!("{storage}#k1"), &inbox, body.as_bytes());
    let verifier = WebhookVerifier::builder()
        .client(Client::new())
        .trusted_storage(Url::parse(&storage).unwrap())
        .build();
    for _ in 0..2 {
        let v = verifier
            .verify("POST", &inbox, &headers, body.as_bytes())
            .await
            .unwrap();
        assert!(v.notification.activities[0].is_update());
        assert_eq!(v.storage.as_str(), storage);
    }
    let mut request = http::Request::builder()
        .method("POST")
        .uri(inbox.as_str())
        .body(body.clone().into_bytes())
        .unwrap();
    *request.headers_mut() = headers.clone();
    verifier.verify_request(&inbox, &request).await.unwrap();
    // A different storage is not trusted.
    let other = WebhookVerifier::builder()
        .trusted_storage(Url::parse("https://other.example/").unwrap())
        .build();
    assert!(
        other
            .verify("POST", &inbox, &headers, body.as_bytes())
            .await
            .unwrap_err()
            .is_signature_verification()
    );
    // Port is part of @authority (the failure triggers one key-rotation refetch, hence two GETs).
    let moved = Url::parse("https://receiver.example/hooks/lws").unwrap();
    assert!(
        verifier
            .verify("POST", &moved, &headers, body.as_bytes())
            .await
            .is_err()
    );
    let _ = Duration::ZERO;
}

// ---------------------------------------------------------------- redirects

#[tokio::test]
async fn redirects_reauthorize_per_hop_and_keep_tokens_in_their_realm() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/lws-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"issuer": base, "token_endpoint": format!("{base}/token")})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token": "tok", "token_type": "Bearer", "expires_in": 300}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage1/a"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("a"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage1/out"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/storage2/x"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage1/in"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/storage1/target"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage1/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("inside"))
        .with_priority(1)
        .mount(&server)
        .await;
    let challenge = format!("Bearer as_uri=\"{base}\", realm=\"{base}/storage1/\"");
    Mock::given(path_prefix_matcher("/storage1/"))
        .respond_with(
            ResponseTemplate::new(401).insert_header("www-authenticate", challenge.as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage2/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("outside"))
        .mount(&server)
        .await;

    let client = Client::builder()
        .authenticator(TokenExchangeAuthenticator::new(OpenIdCredentials::new(
            "id",
        )))
        .build()
        .unwrap();
    assert_eq!(
        client
            .read(url(&server, "/storage1/a"))
            .await
            .unwrap()
            .text()
            .unwrap(),
        "a"
    );
    // Redirect out of the realm (same origin): the token must not follow.
    let out = client.read(url(&server, "/storage1/out")).await.unwrap();
    assert_eq!(out.text().unwrap(), "outside");
    assert_eq!(out.metadata.url, url(&server, "/storage2/x"));
    // Redirect inside the realm: the token is attached again.
    assert_eq!(
        client
            .read(url(&server, "/storage1/in"))
            .await
            .unwrap()
            .text()
            .unwrap(),
        "inside"
    );

    let reqs = requests(&server).await;
    let auth_of = |p: &str| -> Vec<Option<String>> {
        reqs.iter()
            .filter(|r| r.url.path() == p)
            .map(|r| header_str(r, "authorization").map(str::to_owned))
            .collect()
    };
    assert_eq!(auth_of("/storage1/out"), [Some("Bearer tok".to_owned())]);
    assert_eq!(auth_of("/storage2/x"), [None]);
    assert_eq!(auth_of("/storage1/in"), [Some("Bearer tok".to_owned())]);
    assert_eq!(auth_of("/storage1/target"), [Some("Bearer tok".to_owned())]);
}

#[tokio::test]
async fn redirect_method_semantics_and_limits() {
    let a = MockServer::start().await;
    let b = MockServer::start().await; // different port: different origin
    let redirect =
        |code: u16, to: String| ResponseTemplate::new(code).insert_header("location", to.as_str());
    Mock::given(method("GET"))
        .and(path("/cross"))
        .respond_with(redirect(302, format!("{}/x", b.uri())))
        .mount(&a)
        .await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&b)
        .await;
    Mock::given(method("GET"))
        .and(path("/same"))
        .respond_with(redirect(301, "/final".into()))
        .mount(&a)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/same"))
        .respond_with(redirect(301, "/final".into()))
        .mount(&a)
        .await;
    Mock::given(method("GET"))
        .and(path("/see"))
        .respond_with(redirect(303, "/final".into()))
        .mount(&a)
        .await;
    Mock::given(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("final"))
        .mount(&a)
        .await;
    Mock::given(method("QUERY"))
        .and(path("/q"))
        .respond_with(redirect(308, "/q2".into()))
        .mount(&a)
        .await;
    Mock::given(method("QUERY"))
        .and(path("/q2"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"type":"ContainerPage","items":[]}"#,
            "application/lws+json",
        ))
        .mount(&a)
        .await;
    Mock::given(method("POST"))
        .and(path("/post302"))
        .respond_with(redirect(302, "/final".into()))
        .mount(&a)
        .await;
    Mock::given(method("POST"))
        .and(path("/post303"))
        .respond_with(redirect(303, "/final".into()))
        .mount(&a)
        .await;
    Mock::given(method("POST"))
        .and(path("/post307"))
        .respond_with(redirect(307, "/c2/".into()))
        .mount(&a)
        .await;
    Mock::given(method("POST"))
        .and(path("/c2/"))
        .respond_with(ResponseTemplate::new(201).insert_header("location", "/c2/1"))
        .mount(&a)
        .await;
    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(redirect(302, "/loop".into()))
        .mount(&a)
        .await;

    let client = Client::new();
    // An explicit Authorization header is dropped on cross-origin hops, kept on same-origin ones.
    client
        .read(url(&a, "/cross"))
        .header("authorization", "Bearer user")
        .await
        .unwrap();
    let r = client
        .read(url(&a, "/same"))
        .header("authorization", "Bearer user")
        .await
        .unwrap();
    assert_eq!(r.text().unwrap(), "final");
    assert_eq!(
        client.head(url(&a, "/same")).await.unwrap().url,
        url(&a, "/final")
    );
    assert_eq!(
        client.read(url(&a, "/see")).await.unwrap().text().unwrap(),
        "final"
    );
    // QUERY keeps method and body across 308.
    client
        .search_types(url(&a, "/q"), &TypeQuery::new())
        .await
        .unwrap();
    // Unsafe methods follow only 307/308.
    assert_eq!(
        client
            .create(url(&a, "/post302"), "x", "text/plain")
            .await
            .unwrap_err()
            .status()
            .unwrap()
            .as_u16(),
        302
    );
    assert_eq!(
        client
            .create(url(&a, "/post303"), "x", "text/plain")
            .await
            .unwrap_err()
            .status()
            .unwrap()
            .as_u16(),
        303
    );
    let created = client
        .create(url(&a, "/post307"), "x", "text/plain")
        .await
        .unwrap();
    assert_eq!(created.location, url(&a, "/c2/1"));
    // Redirect loops stop after 5 hops.
    assert!(
        client
            .read(url(&a, "/loop"))
            .await
            .unwrap_err()
            .is_protocol()
    );

    let ra = requests(&a).await;
    let rb = requests(&b).await;
    assert!(
        header_str(&rb[0], "authorization").is_none(),
        "credentials must not cross origins"
    );
    let finals: Vec<&Request> = ra.iter().filter(|r| r.url.path() == "/final").collect();
    assert_eq!(header_str(finals[0], "authorization"), Some("Bearer user"));
    assert!(
        finals.iter().all(|r| r.method.as_str() != "POST"),
        "302/303 after POST are not followed"
    );
    let q2 = ra.iter().find(|r| r.url.path() == "/q2").unwrap();
    assert_eq!(q2.method.as_str(), "QUERY");
    assert_eq!(q2.body, b"{}");
    assert_eq!(
        header_str(q2, "content-type"),
        Some("application/lws-query+json")
    );
    let c2 = ra.iter().find(|r| r.url.path() == "/c2/").unwrap();
    assert_eq!(
        (c2.method.as_str(), c2.body.as_slice()),
        ("POST", &b"x"[..])
    );
    assert_eq!(ra.iter().filter(|r| r.url.path() == "/loop").count(), 6);
}
