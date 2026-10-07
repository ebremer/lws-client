// SPDX-License-Identifier: MIT
//! Runs the shared, language-neutral conformance fixtures in `../conformance/fixtures`.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use lws_client::auth::{AuthorizationServerMetadata, TokenResponse, metadata_url, realm_contains};
use lws_client::crypto::{VerifyingKey, jwt};
use lws_client::headers::structured::{BareItem, MemberValue, Parameters, parse_dictionary};
use lws_client::headers::{ProblemDetails, parse_link_headers, parse_www_authenticate};
use lws_client::model::ResourceMetadata;
use lws_client::webhook::signature_base;
use lws_client::*;
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "conformance",
        "fixtures",
        name,
    ]
    .iter()
    .collect();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn headers_from(v: &Value) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in v.as_object().unwrap() {
        let name = HeaderName::try_from(k.as_str()).unwrap();
        match v {
            Value::Array(values) => {
                for x in values {
                    h.append(
                        name.clone(),
                        HeaderValue::from_str(x.as_str().unwrap()).unwrap(),
                    );
                }
            }
            _ => {
                h.append(name, HeaderValue::from_str(v.as_str().unwrap()).unwrap());
            }
        }
    }
    h
}

fn metadata(url: &str, headers: &Value) -> ResourceMetadata {
    ResourceMetadata::from_parts(
        Url::parse(url).unwrap(),
        StatusCode::OK,
        headers_from(headers),
    )
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn link_headers() {
    let f = fixture("link-headers.json");
    for case in f["cases"].as_array().unwrap() {
        let base = Url::parse(case["base"].as_str().unwrap()).unwrap();
        let headers = strs(&case["headers"]);
        let links = parse_link_headers(headers.iter().map(String::as_str), &base);
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(links.len(), expected.len(), "case {}", case["name"]);
        for (l, e) in links.iter().zip(expected) {
            assert_eq!(l.href.as_str(), e["href"], "case {}", case["name"]);
            assert_eq!(l.rel, e["rel"].as_str().unwrap(), "case {}", case["name"]);
            let params: serde_json::Map<String, Value> = l
                .params
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect();
            assert_eq!(Value::Object(params), e["params"], "case {}", case["name"]);
        }
    }
}

#[test]
fn www_authenticate() {
    let f = fixture("www-authenticate.json");
    for case in f["cases"].as_array().unwrap() {
        let headers = strs(&case["headers"]);
        let got = parse_www_authenticate(headers.iter().map(String::as_str));
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(got.len(), expected.len(), "case {}", case["name"]);
        for (c, e) in got.iter().zip(expected) {
            assert!(
                c.scheme.eq_ignore_ascii_case(e["scheme"].as_str().unwrap()),
                "case {}",
                case["name"]
            );
            let params: serde_json::Map<String, Value> = c
                .params
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect();
            assert_eq!(Value::Object(params), e["params"], "case {}", case["name"]);
            assert_eq!(
                c.token68.as_deref(),
                e.get("token68").and_then(Value::as_str),
                "case {}",
                case["name"]
            );
        }
    }
}

fn typed(item: &BareItem) -> Value {
    use base64::Engine as _;
    match item {
        BareItem::Integer(n) => json!({"integer": n}),
        BareItem::Decimal(d) => json!({"decimal": d}),
        BareItem::String(s) => json!({"string": s}),
        BareItem::Token(t) => json!({"token": t}),
        BareItem::ByteSequence(b) => {
            json!({"bytes": base64::engine::general_purpose::STANDARD.encode(b)})
        }
        BareItem::Boolean(b) => json!({"boolean": b}),
        BareItem::Date(n) => json!({"date": n}),
        BareItem::DisplayString(s) => json!({"displayString": s}),
    }
}

fn typed_params(p: &Parameters) -> Value {
    Value::Object(p.iter().map(|(k, v)| (k.to_owned(), typed(v))).collect())
}

#[test]
fn structured_fields() {
    let f = fixture("structured-fields.json");
    for case in f["cases"].as_array().unwrap() {
        let parsed = parse_dictionary(case["input"].as_str().unwrap());
        if case["error"] == json!(true) {
            assert!(parsed.is_err(), "case {} should fail", case["name"]);
            continue;
        }
        let dict = parsed.unwrap_or_else(|e| panic!("case {}: {e}", case["name"]));
        let mut got = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let member = match v {
                MemberValue::Item(i) => {
                    json!({"item": typed(&i.value), "params": typed_params(&i.params)})
                }
                MemberValue::InnerList(l) => json!({
                    "innerList": l.items.iter().map(|i| json!({"item": typed(&i.value), "params": typed_params(&i.params)})).collect::<Vec<_>>(),
                    "params": typed_params(&l.params),
                }),
            };
            got.insert(k.to_owned(), member);
        }
        assert_eq!(
            Value::Object(got),
            case["expected"],
            "case {}",
            case["name"]
        );
        if let Some(ser) = case.get("serialized").and_then(Value::as_object) {
            for (k, v) in ser {
                assert_eq!(
                    dict.get(k).unwrap().serialize(),
                    v.as_str().unwrap(),
                    "case {} member {k}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn json_patch_and_pointer() {
    let f = fixture("json-patch.json");
    for e in f["pointerEscapes"].as_array().unwrap() {
        assert_eq!(
            JsonPointer::escape(e["segment"].as_str().unwrap()),
            e["escaped"].as_str().unwrap()
        );
        assert_eq!(
            JsonPointer::unescape(e["escaped"].as_str().unwrap()),
            e["segment"].as_str().unwrap()
        );
    }
    for p in f["pointers"].as_array().unwrap() {
        assert_eq!(
            JsonPointer::from_segments(strs(&p["segments"])).as_str(),
            p["pointer"].as_str().unwrap()
        );
    }
    let ops = &f["patch"]["operations"];
    let patch = JsonPatch::new()
        .add("/linkset/0/license", ops[0]["value"].clone())
        .remove("/linkset/0/describedby/0")
        .replace("/name", "Alice")
        .move_value("/a", "/b")
        .copy("/b", "/c")
        .test("/age", 30);
    assert_eq!(patch.to_json(), *ops);
}

#[test]
fn type_queries() {
    let f = fixture("type-queries.json");
    for case in f["cases"].as_array().unwrap() {
        let mut q = TypeQuery::new();
        for step in case["steps"].as_array().unwrap() {
            let key = step["key"].as_str().unwrap();
            if let Some(v) = step.get("allOf") {
                q = if key == "type" {
                    q.all_of(strs(v))
                } else {
                    q.relation(key).all_of(strs(v))
                };
            } else {
                let v = &step["anyOf"];
                q = if key == "type" {
                    q.any_of(strs(v))
                } else {
                    q.relation(key).any_of(strs(v))
                };
            }
        }
        if case["error"] == json!(true) {
            assert!(q.to_json().is_err(), "case {} should fail", case["name"]);
        } else {
            assert_eq!(q.to_json().unwrap(), case["json"], "case {}", case["name"]);
        }
    }
}

#[test]
fn did_key_vectors() {
    let f = fixture("did-key.json");
    for v in f["vectors"].as_array().unwrap() {
        let key = VerifyingKey::from_jwk_json(&v["publicJwk"]).unwrap();
        let d = key.did_key();
        assert_eq!(d.did, v["did"].as_str().unwrap(), "vector {}", v["name"]);
        assert_eq!(d.kid, v["kid"].as_str().unwrap(), "vector {}", v["name"]);
        assert_eq!(VerifyingKey::from_did_key(&d.did).unwrap(), key);
    }
}

#[test]
fn jwt_vectors() {
    let f = fixture("jwt.json");
    for v in f["vectors"].as_array().unwrap() {
        let key = VerifyingKey::from_jwk_json(&v["publicJwk"]).unwrap();
        let (header, claims) = jwt::verify(v["jwt"].as_str().unwrap(), &key).unwrap();
        assert_eq!(header, v["header"]);
        assert_eq!(claims, v["claims"]);
        // The did:key subject resolves to the same key.
        assert_eq!(
            VerifyingKey::from_did_key(claims["sub"].as_str().unwrap()).unwrap(),
            key
        );
        // Tampering breaks the signature.
        let token = v["jwt"].as_str().unwrap();
        let (input, sig) = token.rsplit_once('.').unwrap();
        let tampered = format!("{input}x.{sig}");
        assert!(jwt::verify(&tampered, &key).is_err());
    }
}

#[test]
fn webhook_vectors() {
    let index = fixture("webhook/index.json");
    let description_json = fixture("webhook/storage-description.json");
    let description = StorageDescription::from_json(
        &Url::parse("https://storage.example/").unwrap(),
        description_json,
    )
    .unwrap();
    let mut valid = 0;
    let mut invalid = 0;
    for name in index["vectors"].as_array().unwrap() {
        let v = fixture(&format!("webhook/{}", name.as_str().unwrap()));
        let now = UNIX_EPOCH + Duration::from_secs(v["now"].as_u64().unwrap());
        let verifier = WebhookVerifier::builder().clock(move || now).build();
        let headers = headers_from(&v["headers"]);
        let url = Url::parse(v["url"].as_str().unwrap()).unwrap();
        let result = verifier.verify_with_description(
            v["method"].as_str().unwrap(),
            &url,
            &headers,
            v["body"].as_str().unwrap().as_bytes(),
            &description,
        );
        let expected = &v["expected"];
        if expected["valid"] == json!(true) {
            valid += 1;
            let verified = result.unwrap_or_else(|e| panic!("vector {}: {e}", v["name"]));
            assert_eq!(verified.key_id, expected["keyid"].as_str().unwrap());
            let n = &expected["notification"];
            assert_eq!(
                verified.notification.storage,
                n["storage"].as_str().unwrap()
            );
            for (a, e) in verified
                .notification
                .activities
                .iter()
                .zip(n["activities"].as_array().unwrap())
            {
                assert_eq!(a.types, strs(&e["types"]));
                assert_eq!(a.object.id, e["objectId"].as_str().unwrap());
                assert_eq!(a.target.as_deref(), e.get("target").and_then(Value::as_str));
            }
            // The signature base matches the generator's byte for byte.
            let input = parse_dictionary(headers.get("signature-input").unwrap().to_str().unwrap())
                .unwrap();
            let MemberValue::InnerList(params) = input.get("sig1").unwrap() else {
                panic!()
            };
            assert_eq!(
                signature_base("POST", &url, &headers, params).unwrap(),
                v["signatureBase"].as_str().unwrap()
            );
        } else {
            invalid += 1;
            let err = result
                .err()
                .unwrap_or_else(|| panic!("vector {} must fail", v["name"]));
            assert!(
                err.is_signature_verification(),
                "vector {}: {err}",
                v["name"]
            );
        }
    }
    assert_eq!((valid, invalid), (3, 10));
}

#[test]
fn storage_description() {
    let f = fixture("responses/storage-description.json");
    let url = Url::parse(f["url"].as_str().unwrap()).unwrap();
    let sd = StorageDescription::from_json(&url, f["body"].clone()).unwrap();
    let e = &f["expected"];
    assert_eq!(sd.id.as_str(), e["id"]);
    assert_eq!(sd.types, strs(&e["types"]));
    assert_eq!(sd.storage_root().unwrap().as_str(), e["storageRoot"]);
    let ns = sd.notification_service().unwrap();
    assert_eq!(ns.service_endpoint.as_str(), e["notificationService"]);
    assert_eq!(
        ns.subscription_types(),
        strs(&e["notificationSubscriptionTypes"])
    );
    assert_eq!(
        sd.type_index_service().unwrap().service_endpoint.as_str(),
        e["typeIndexService"]
    );
    assert_eq!(
        sd.type_search_service().unwrap().service_endpoint.as_str(),
        e["typeSearchService"]
    );
    assert_eq!(
        sd.access_request_service()
            .unwrap()
            .service_endpoint
            .as_str(),
        e["accessRequestService"]
    );
    assert_eq!(
        sd.access_grant_service().unwrap().service_endpoint.as_str(),
        e["accessGrantService"]
    );
    assert_eq!(
        sd.services.len() as u64,
        e["serviceCount"].as_u64().unwrap()
    );
    let caps: Vec<String> = sd
        .capabilities
        .iter()
        .flat_map(|c| c.types.clone())
        .collect();
    assert_eq!(caps, strs(&e["capabilityTypes"]));
    let custom = sd
        .service(e["customService"]["type"].as_str().unwrap())
        .unwrap();
    assert_eq!(custom.id.as_deref(), e["customService"]["id"].as_str());
    assert_eq!(
        custom.service_endpoint.as_str(),
        e["customService"]["serviceEndpoint"]
    );
    assert!(
        sd.capability("https://feature.example/PatchSupport")
            .unwrap()
            .property("format")
            .is_some()
    );

    assert!(
        StorageDescription::from_json(&url, f["invalid"]["notStorage"].clone())
            .unwrap_err()
            .is_protocol()
    );
    let no_root = StorageDescription::from_json(&url, f["invalid"]["noRoot"].clone()).unwrap();
    assert!(no_root.storage_root().unwrap_err().is_protocol());
}

#[test]
fn container_page() {
    let f = fixture("responses/container-page.json");
    let page = ContainerPage::parse(
        metadata(f["url"].as_str().unwrap(), &f["headers"]),
        f["body"].to_string().as_bytes(),
    )
    .unwrap();
    let e = &f["expected"];
    let opt = |u: &Option<Url>| u.as_ref().map(|u| json!(u.as_str())).unwrap_or(Value::Null);
    assert_eq!(page.id.as_str(), e["id"]);
    assert_eq!(
        page.metadata.is_container(),
        e["isContainer"].as_bool().unwrap()
    );
    assert_eq!(page.total_items, e["totalItems"].as_u64());
    assert_eq!(page.etag(), e["etag"].as_str());
    assert_eq!(page.metadata.linkset().unwrap().as_str(), e["linkset"]);
    assert_eq!(page.metadata.parent().unwrap().as_str(), e["parent"]);
    assert_eq!(page.metadata.storage().unwrap().as_str(), e["storage"]);
    assert_eq!(opt(&page.first), e["first"]);
    assert_eq!(opt(&page.next), e["next"]);
    assert_eq!(opt(&page.prev), e["prev"]);
    assert_eq!(opt(&page.last), e["last"]);
    let items = e["items"].as_array().unwrap();
    assert_eq!(page.items.len(), items.len());
    for (i, x) in page.items.iter().zip(items) {
        assert_eq!(i.id.as_str(), x["id"]);
        assert_eq!(i.is_container(), x["isContainer"].as_bool().unwrap());
        assert_eq!(i.is_data_resource(), x["isDataResource"].as_bool().unwrap());
        assert_eq!(i.format.as_deref(), x["format"].as_str());
        assert_eq!(i.size, x["size"].as_u64());
        assert_eq!(i.types, strs(&x["types"]));
        match x.get("modified").and_then(Value::as_str) {
            Some(m) => assert_eq!(lws_client::datetime::format_rfc3339(i.modified.unwrap()), m),
            None => assert!(i.modified.is_none()),
        }
        if let Some(raw) = x.get("modifiedRaw") {
            assert_eq!(i.modified_raw.as_deref(), raw.as_str());
        }
        if let Some(t) = x.get("hasType").and_then(Value::as_str) {
            assert!(i.has_type(t));
        }
    }
    // A non-container response is rejected.
    let not_container = metadata(
        "https://s.example/a.txt",
        &json!({"content-type": "application/json"}),
    );
    assert!(
        ContainerPage::parse(not_container, br#"{"type":"DataResource"}"#)
            .unwrap_err()
            .is_protocol()
    );
    let wrong_type = metadata(
        "https://s.example/c/",
        &json!({"content-type": "text/turtle", "link": "<https://www.w3.org/ns/lws#Container>; rel=type"}),
    );
    assert!(
        ContainerPage::parse(wrong_type, b"")
            .unwrap_err()
            .is_protocol()
    );
}

#[test]
fn linkset() {
    let f = fixture("responses/linkset.json");
    let md = metadata(f["url"].as_str().unwrap(), &f["headers"]);
    let e = &f["expected"];
    assert_eq!(md.etag.as_deref(), e["etag"].as_str());
    assert_eq!(md.allow, strs(&e["allow"]));
    assert_eq!(md.accept_patch, strs(&e["acceptPatch"]));
    let mut ls = Linkset::from_json(&f["body"]).unwrap();
    assert_eq!(ls.contexts.len() as u64, e["contexts"].as_u64().unwrap());
    assert_eq!(ls.contexts[0].anchor.as_deref(), e["anchor"].as_str());
    assert_eq!(ls.links().len() as u64, e["linkCount"].as_u64().unwrap());
    for (rel, targets) in e["targets"].as_object().unwrap() {
        assert_eq!(ls.targets(rel), strs(targets), "rel {rel}");
    }
    assert_eq!(ls.to_json(), f["body"], "round trip");
    let op = &e["afterAdd"]["operation"];
    ls.add(
        op["anchor"].as_str().unwrap(),
        op["rel"].as_str().unwrap(),
        op["href"].as_str().unwrap(),
        None,
    );
    assert_eq!(
        ls.targets("license"),
        strs(&e["afterAdd"]["licenseTargets"])
    );
    assert_eq!(
        ls.remove(
            op["anchor"].as_str().unwrap(),
            "license",
            Some(op["href"].as_str().unwrap())
        ),
        1
    );
    assert_eq!(ls.to_json(), f["body"]);
}

#[test]
fn notifications() {
    let f = fixture("responses/notification.json");
    for (doc, exp) in [("single", "singleExpected"), ("batch", "batchExpected")] {
        let n = Notification::from_json(f[doc].clone()).unwrap();
        let e = &f[exp];
        assert_eq!(n.storage, e["storage"].as_str().unwrap());
        let acts = e["activities"].as_array().unwrap();
        assert_eq!(n.activities.len(), acts.len());
        for (a, x) in n.activities.iter().zip(acts) {
            assert_eq!(a.id, x["id"].as_str().unwrap());
            assert_eq!(a.types, strs(&x["types"]));
            assert_eq!(a.object.id, x["objectId"].as_str().unwrap());
            if let Some(t) = x.get("objectTypes") {
                assert_eq!(a.object.types, strs(t));
            }
            for (flag, f) in [
                ("isCreate", a.is_create()),
                ("isUpdate", a.is_update()),
                ("isDelete", a.is_delete()),
            ] {
                if let Some(v) = x.get(flag) {
                    assert_eq!(v.as_bool().unwrap(), f);
                }
            }
            for (k, v) in [
                ("target", &a.target),
                ("origin", &a.origin),
                ("actor", &a.actor),
            ] {
                assert_eq!(v.as_deref(), x.get(k).and_then(Value::as_str), "{k}");
            }
            if let Some(p) = x.get("published").and_then(Value::as_str) {
                assert_eq!(
                    lws_client::datetime::format_rfc3339(a.published.unwrap()),
                    p
                );
            }
        }
    }
    assert!(
        Notification::from_json(f["invalid"].clone())
            .unwrap_err()
            .is_protocol()
    );
}

#[test]
fn access_documents() {
    let f = fixture("responses/access.json");
    let req = AccessRequest::from_json(f["request"].clone()).unwrap();
    assert_eq!(req.to_json(), f["request"]);
    let grant = AccessGrant::from_json(f["grant"].clone()).unwrap();
    assert_eq!(grant.to_json(), f["grant"]);
    assert_eq!(
        grant.access[0].constraints[0].right_operand,
        json!(["image/jpeg", "image/png"])
    );
    assert!(AccessGrant::from_json(f["request"].clone()).is_err());

    let built = AccessRequest::builder("https://storage.example/")
        .inbox("https://id.example/agent/inbox/")
        .policy(
            AccessPolicy::builder("https://id.example/agent")
                .actions(["read", "create"])
                .target_resources(["https://storage.example/root/projects/"])
                .constraint(Constraint::purpose("https://purpose.example/collaboration"))
                .constraint(Constraint::not_after("2026-06-09T10:00:00Z"))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    assert_eq!(built.to_json(), f["request"]);
    assert!(
        AccessRequest::builder("https://storage.example/")
            .build()
            .is_err()
    );
    assert!(
        AccessPolicy::builder("https://id.example/agent")
            .build()
            .is_err()
    );
}

#[test]
fn type_index_and_search_pages() {
    let f = fixture("responses/type-index.json");
    let ti = &f["typeIndex"];
    let page = TypeIndexPage::parse(
        metadata(ti["url"].as_str().unwrap(), &ti["headers"]),
        ti["body"].to_string().as_bytes(),
    )
    .unwrap();
    assert_eq!(page.total_items, ti["expected"]["totalItems"].as_u64());
    assert_eq!(page.types, strs(&ti["expected"]["types"]));
    assert_eq!(page.next.unwrap().as_str(), ti["expected"]["next"]);
    let s = &f["search"];
    let page = SearchPage::parse(
        metadata(s["url"].as_str().unwrap(), &s["headers"]),
        s["body"].to_string().as_bytes(),
    )
    .unwrap();
    assert_eq!(page.total_items, s["expected"]["totalItems"].as_u64());
    let page_id = s["body"]["id"]
        .as_str()
        .unwrap_or_else(|| s["url"].as_str().unwrap());
    assert_eq!(page.id.as_str(), page_id);
    let ids: Vec<&str> = page.items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, strs(&s["expected"]["ids"]));
    assert_eq!(page.next.unwrap().as_str(), s["expected"]["next"]);
}

#[test]
fn oauth() {
    let f = fixture("responses/oauth.json");
    let m = AuthorizationServerMetadata::from_json(f["metadata"].clone()).unwrap();
    assert_eq!(
        m.token_endpoint.as_str(),
        "https://authorization.example/token"
    );
    assert!(
        m.subject_token_types_supported
            .unwrap()
            .contains(&"urn:ietf:params:oauth:token-type:jwt".to_owned())
    );
    for c in f["metadataUrls"].as_array().unwrap() {
        assert_eq!(
            metadata_url(&Url::parse(c["issuer"].as_str().unwrap()).unwrap()).as_str(),
            c["url"]
        );
    }
    let now = SystemTime::now();
    let t = TokenResponse::from_json(f["tokenResponse"]["body"].clone()).unwrap();
    assert_eq!(
        t.expires_at(now),
        now + Duration::from_secs(f["tokenResponse"]["expectedExpiresIn"].as_u64().unwrap())
    );
    let t = TokenResponse::from_json(f["tokenResponseNoExpiry"]["body"].clone()).unwrap();
    assert_eq!(
        t.expires_at(now),
        UNIX_EPOCH
            + Duration::from_secs(f["tokenResponseNoExpiry"]["expectedExp"].as_u64().unwrap())
    );
    for c in f["realmChecks"].as_array().unwrap() {
        let realm = Url::parse(c["realm"].as_str().unwrap()).unwrap();
        let url = Url::parse(c["url"].as_str().unwrap()).unwrap();
        assert_eq!(
            realm_contains(&realm, &url),
            c["contained"].as_bool().unwrap(),
            "{realm} vs {url}"
        );
    }
}

#[test]
fn problem_details() {
    let f = fixture("responses/problem-details.json");
    let problem = ProblemDetails::from_json(&f["body"]);
    let err = Error::from_http(HttpError {
        status: StatusCode::from_u16(f["status"].as_u64().unwrap() as u16).unwrap(),
        method: http::Method::DELETE,
        url: Url::parse("https://storage.example/alice/notes/").unwrap(),
        headers: headers_from(&f["headers"]),
        problem,
        body: f["body"].to_string(),
        challenges: Vec::new(),
    });
    assert!(matches!(err, Error::Conflict(_)));
    let p = err.problem().unwrap();
    let e = &f["expected"];
    assert_eq!(p.problem_type.as_deref(), e["type"].as_str());
    assert_eq!(p.title.as_deref(), e["title"].as_str());
    assert_eq!(p.detail.as_deref(), e["detail"].as_str());
    assert_eq!(p.instance.as_deref(), e["instance"].as_str());
    assert_eq!(p.extensions["itemCount"], e["extension"]["itemCount"]);
}

#[test]
fn subscription() {
    let f = fixture("responses/subscription.json");
    let input = &f["input"];
    let topics = strs(&input["topics"])
        .into_iter()
        .map(|t| Url::parse(&t).unwrap());
    let req = WebhookSubscriptionRequest::new(
        topics,
        Url::parse(input["inbox"].as_str().unwrap()).unwrap(),
    )
    .expires(lws_client::datetime::parse_rfc3339(input["expires"].as_str().unwrap()).unwrap());
    assert_eq!(req.to_json(), f["expectedRequestBody"]);
    let base = Url::parse("https://notification.example/subscriptions").unwrap();
    let sub = Subscription::from_json(
        f["response"]["body"].clone(),
        &base,
        None,
        "WebhookSubscription",
    )
    .unwrap();
    assert_eq!(
        sub.subscription_type,
        f["expected"]["type"].as_str().unwrap()
    );
    assert_eq!(sub.subscription.as_str(), f["expected"]["subscription"]);
    assert_eq!(
        sub.expires_raw.as_deref(),
        f["expected"]["expires"].as_str()
    );
}

#[test]
fn url_parse_errors_convert_to_invalid_input() {
    fn parse(s: &str) -> lws_client::Result<url::Url> {
        Ok(url::Url::parse(s)?)
    }
    let err = parse("not a url").unwrap_err();
    assert!(matches!(err, lws_client::Error::InvalidInput(_)), "{err:?}");
}
